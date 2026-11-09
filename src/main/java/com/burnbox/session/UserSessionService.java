package com.burnbox.session;

import com.burnbox.platform.SecurityEventPublisher;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserSessionService {

    public static final Duration INACTIVITY_TIMEOUT = Duration.ofMinutes(30);
    public static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(12);

    private final UserSessionRepository repository;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final SecurityEventPublisher securityEventPublisher;
    private final Clock clock;

    public UserSessionService(
            UserSessionRepository repository,
            ApplicationEventPublisher applicationEventPublisher,
            SecurityEventPublisher securityEventPublisher,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.applicationEventPublisher = Objects.requireNonNull(applicationEventPublisher, "applicationEventPublisher must not be null");
        this.securityEventPublisher = Objects.requireNonNull(securityEventPublisher, "securityEventPublisher must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Transactional
    public UserSessionMeta registerSession(String sessionId, UUID userId, String ipHash, String userAgentSummary) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(ipHash, "ipHash must not be null");

        Instant now = Instant.now(clock);
        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(),
                sessionId,
                userId,
                ipHash,
                userAgentSummary != null ? userAgentSummary : "Navegador Desconocido",
                now,
                now,
                false
        );

        repository.insertSession(session);

        applicationEventPublisher.publishEvent(new SessionCreated(sessionId, userId, now));
        securityEventPublisher.publish("SESSION_CREATED", "session", sessionId, Map.of(
                "userId", userId.toString(),
                "ipHash", ipHash
        ));

        return session;
    }

    @Transactional
    public SessionValidationResult validateAndTouch(String sessionId) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Instant now = Instant.now(clock);

        Optional<UserSessionMeta> sessionOpt = repository.findBySessionId(sessionId);
        if (sessionOpt.isEmpty()) {
            return SessionValidationResult.NOT_FOUND;
        }

        UserSessionMeta session = sessionOpt.get();
        if (session.revoked()) {
            return SessionValidationResult.REVOKED;
        }

        // BR-001: Absolute timeout check (12 hours)
        if (session.createdAt().plus(ABSOLUTE_TIMEOUT).isBefore(now)) {
            repository.markRevoked(sessionId);
            applicationEventPublisher.publishEvent(new SessionExpired(sessionId, session.userId(), now, "ABSOLUTE_TIMEOUT"));
            securityEventPublisher.publish("SESSION_EXPIRED", "session", sessionId, Map.of(
                    "userId", session.userId().toString(),
                    "reason", "ABSOLUTE_TIMEOUT"
            ));
            return SessionValidationResult.EXPIRED_ABSOLUTE;
        }

        // BR-001: Inactivity timeout check (30 minutes)
        if (session.lastAccessedAt().plus(INACTIVITY_TIMEOUT).isBefore(now)) {
            repository.markRevoked(sessionId);
            applicationEventPublisher.publishEvent(new SessionExpired(sessionId, session.userId(), now, "INACTIVITY_TIMEOUT"));
            securityEventPublisher.publish("SESSION_EXPIRED", "session", sessionId, Map.of(
                    "userId", session.userId().toString(),
                    "reason", "INACTIVITY_TIMEOUT"
            ));
            return SessionValidationResult.EXPIRED_INACTIVITY;
        }

        // Touch session
        repository.updateLastAccessed(sessionId, now);
        return SessionValidationResult.VALID;
    }

    @Transactional(readOnly = true)
    public List<UserSessionMeta> listActiveSessions(UUID userId) {
        Objects.requireNonNull(userId, "userId must not be null");
        Instant now = Instant.now(clock);

        return repository.findActiveByUserId(userId).stream()
                .filter(s -> !s.createdAt().plus(ABSOLUTE_TIMEOUT).isBefore(now))
                .filter(s -> !s.lastAccessedAt().plus(INACTIVITY_TIMEOUT).isBefore(now))
                .toList();
    }

    @Transactional
    public boolean revokeSession(UUID userId, String sessionId) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Instant now = Instant.now(clock);

        Optional<UserSessionMeta> sessionOpt = repository.findBySessionId(sessionId);
        if (sessionOpt.isEmpty()) {
            return false;
        }

        UserSessionMeta session = sessionOpt.get();
        // BR-003: Check ownership
        if (!session.userId().equals(userId)) {
            securityEventPublisher.publish("SESSION_REVOCATION_REJECTED", "session", sessionId, Map.of(
                    "attemptedBy", userId.toString(),
                    "actualOwner", session.userId().toString()
            ));
            throw new SecurityException("No tiene autorización para revocar una sesión ajena");
        }

        repository.markRevoked(sessionId);

        applicationEventPublisher.publishEvent(new SessionRevoked(sessionId, userId, now, "USER_MANUAL_REVOCATION"));
        securityEventPublisher.publish("SESSION_REVOKED", "session", sessionId, Map.of(
                "userId", userId.toString()
        ));

        return true;
    }

    @Transactional
    public void revokeOtherSessions(UUID userId, String currentSessionId) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(currentSessionId, "currentSessionId must not be null");
        Instant now = Instant.now(clock);

        repository.revokeOthersForUser(userId, currentSessionId);

        applicationEventPublisher.publishEvent(new SessionRevoked(
                currentSessionId, userId, now, "REVOKE_OTHERS"
        ));
        securityEventPublisher.publish("SESSION_REVOKE_OTHERS", "user", userId.toString(), Map.of(
                "currentSessionId", currentSessionId
        ));
    }
}
