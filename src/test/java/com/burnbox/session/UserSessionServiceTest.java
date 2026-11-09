package com.burnbox.session;

import com.burnbox.platform.SecurityEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserSessionServiceTest {

    @Mock
    private UserSessionRepository repository;

    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    @Mock
    private SecurityEventPublisher securityEventPublisher;

    private Clock clock;
    private UserSessionService service;
    private final Instant baseTime = Instant.parse("2026-11-09T16:00:00Z");

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(baseTime, ZoneOffset.UTC);
        service = new UserSessionService(repository, applicationEventPublisher, securityEventPublisher, clock);
    }

    @Test
    @DisplayName("AC-001: Creación de sesión registra metadatos con IP hasheada y fecha de creación")
    void registersSessionWithHashedIpAndCreatedAt() {
        UUID userId = UUID.randomUUID();
        String sessionId = "sess-12345";
        String ipHash = "hash-999999999999";
        String ua = "Mozilla/5.0 Chrome/130";

        UserSessionMeta session = service.registerSession(sessionId, userId, ipHash, ua);

        assertThat(session).isNotNull();
        assertThat(session.sessionId()).isEqualTo(sessionId);
        assertThat(session.userId()).isEqualTo(userId);
        assertThat(session.ipHash()).isEqualTo(ipHash);
        assertThat(session.createdAt()).isEqualTo(baseTime);
        assertThat(session.lastAccessedAt()).isEqualTo(baseTime);

        verify(repository).insertSession(session);
        verify(applicationEventPublisher).publishEvent(any(SessionCreated.class));
        verify(securityEventPublisher).publish(eq("SESSION_CREATED"), eq("session"), eq(sessionId), any());
    }

    @Test
    @DisplayName("AC-002 / AF-01 / BR-001: Sesión inactiva por más de 30 minutos es invalidada por inactividad")
    void inactivityTimeoutAfter30Minutes() {
        String sessionId = "sess-inactivity";
        UUID userId = UUID.randomUUID();
        // Last accessed 31 minutes ago, created 35 minutes ago
        Instant created = baseTime.minus(Duration.ofMinutes(35));
        Instant lastAccessed = baseTime.minus(Duration.ofMinutes(31));

        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(), sessionId, userId, "ip-hash", "Safari", created, lastAccessed, false
        );

        when(repository.findBySessionId(sessionId)).thenReturn(Optional.of(session));

        SessionValidationResult result = service.validateAndTouch(sessionId);

        assertThat(result).isEqualTo(SessionValidationResult.EXPIRED_INACTIVITY);
        verify(repository).markRevoked(sessionId);
        verify(applicationEventPublisher).publishEvent(any(SessionExpired.class));
        verify(securityEventPublisher).publish(eq("SESSION_EXPIRED"), eq("session"), eq(sessionId), any());
    }

    @Test
    @DisplayName("AC-003 / AF-02 / BR-001: Sesión con antigüedad mayor a 12 horas es invalidada por timeout absoluto")
    void absoluteTimeoutAfter12Hours() {
        String sessionId = "sess-absolute";
        UUID userId = UUID.randomUUID();
        // Created 12 hours and 1 minute ago, even if accessed 5 minutes ago!
        Instant created = baseTime.minus(Duration.ofHours(12).plusMinutes(1));
        Instant lastAccessed = baseTime.minus(Duration.ofMinutes(5));

        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(), sessionId, userId, "ip-hash", "Firefox", created, lastAccessed, false
        );

        when(repository.findBySessionId(sessionId)).thenReturn(Optional.of(session));

        SessionValidationResult result = service.validateAndTouch(sessionId);

        assertThat(result).isEqualTo(SessionValidationResult.EXPIRED_ABSOLUTE);
        verify(repository).markRevoked(sessionId);
        verify(applicationEventPublisher).publishEvent(any(SessionExpired.class));
    }

    @Test
    @DisplayName("BR-001: Sesión activa y reciente se actualiza y permanece válida")
    void touchSessionWithinTimeoutKeepsItValid() {
        String sessionId = "sess-active";
        UUID userId = UUID.randomUUID();
        Instant created = baseTime.minus(Duration.ofHours(2));
        Instant lastAccessed = baseTime.minus(Duration.ofMinutes(10));

        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(), sessionId, userId, "ip-hash", "Chrome", created, lastAccessed, false
        );

        when(repository.findBySessionId(sessionId)).thenReturn(Optional.of(session));

        SessionValidationResult result = service.validateAndTouch(sessionId);

        assertThat(result).isEqualTo(SessionValidationResult.VALID);
        verify(repository).updateLastAccessed(sessionId, baseTime);
    }

    @Test
    @DisplayName("AC-004 / BR-003: listActiveSessions lista únicamente sesiones activas no vencidas del usuario")
    void listActiveSessionsOnlyReturnsNonExpiredNonRevokedForUser() {
        UUID userId = UUID.randomUUID();

        UserSessionMeta validSession = new UserSessionMeta(
                UUID.randomUUID(), "sess-valid", userId, "ip1", "Chrome",
                baseTime.minus(Duration.ofHours(1)), baseTime.minus(Duration.ofMinutes(5)), false
        );
        UserSessionMeta expiredInactivity = new UserSessionMeta(
                UUID.randomUUID(), "sess-exp1", userId, "ip2", "Firefox",
                baseTime.minus(Duration.ofHours(2)), baseTime.minus(Duration.ofMinutes(35)), false
        );
        UserSessionMeta expiredAbsolute = new UserSessionMeta(
                UUID.randomUUID(), "sess-exp2", userId, "ip3", "Safari",
                baseTime.minus(Duration.ofHours(13)), baseTime.minus(Duration.ofMinutes(1)), false
        );

        when(repository.findActiveByUserId(userId)).thenReturn(List.of(validSession, expiredInactivity, expiredAbsolute));

        List<UserSessionMeta> activeSessions = service.listActiveSessions(userId);

        assertThat(activeSessions).containsExactly(validSession);
    }

    @Test
    @DisplayName("AC-005 / BR-004: Revocación unitaria marca la sesión como revocada y emite SessionRevoked")
    void revokeSessionMarksRevokedAndEmitsEvent() {
        UUID userId = UUID.randomUUID();
        String sessionId = "sess-to-revoke";

        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(), sessionId, userId, "ip-hash", "Chrome",
                baseTime.minus(Duration.ofHours(1)), baseTime.minus(Duration.ofMinutes(5)), false
        );

        when(repository.findBySessionId(sessionId)).thenReturn(Optional.of(session));

        boolean revoked = service.revokeSession(userId, sessionId);

        assertThat(revoked).isTrue();
        verify(repository).markRevoked(sessionId);
        verify(applicationEventPublisher).publishEvent(any(SessionRevoked.class));
        verify(securityEventPublisher).publish(eq("SESSION_REVOKED"), eq("session"), eq(sessionId), any());
    }

    @Test
    @DisplayName("BR-003: Intentar revocar la sesión de otro usuario lanza SecurityException")
    void revokeSessionThrowsWhenNotOwner() {
        UUID ownerId = UUID.randomUUID();
        UUID attackerId = UUID.randomUUID();
        String sessionId = "sess-victim";

        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(), sessionId, ownerId, "ip-hash", "Chrome",
                baseTime.minus(Duration.ofHours(1)), baseTime.minus(Duration.ofMinutes(5)), false
        );

        when(repository.findBySessionId(sessionId)).thenReturn(Optional.of(session));

        assertThatThrownBy(() -> service.revokeSession(attackerId, sessionId))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("No tiene autorización");

        verify(repository, never()).markRevoked(any());
        verify(securityEventPublisher).publish(eq("SESSION_REVOCATION_REJECTED"), eq("session"), eq(sessionId), any());
    }

    @Test
    @DisplayName("AC-006 / AF-03: Revocación masiva revoca todas las demás sesiones preservando la actual")
    void revokeOthersPreservesCurrentSession() {
        UUID userId = UUID.randomUUID();
        String currentSessionId = "sess-current";

        service.revokeOtherSessions(userId, currentSessionId);

        verify(repository).revokeOthersForUser(userId, currentSessionId);
        verify(applicationEventPublisher).publishEvent(any(SessionRevoked.class));
        verify(securityEventPublisher).publish(eq("SESSION_REVOKE_OTHERS"), eq("user"), eq(userId.toString()), any());
    }
}
