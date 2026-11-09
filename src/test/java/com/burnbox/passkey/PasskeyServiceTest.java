package com.burnbox.passkey;

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
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasskeyServiceTest {

    @Mock
    private PasskeyRepository repository;

    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    @Mock
    private SecurityEventPublisher securityEventPublisher;

    private Clock clock;
    private PasskeyService service;
    private final Instant baseTime = Instant.parse("2026-11-09T16:00:00Z");

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(baseTime, ZoneOffset.UTC);
        service = new PasskeyService(repository, applicationEventPublisher, securityEventPublisher, clock);
    }

    @Test
    @DisplayName("AC-001 / BR-001: Primer passkey registrado entra en cuarentena PENDING_ACTIVATION por 24h")
    void enrollFirstPasskeyEntersPendingActivationFor24Hours() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};
        byte[] pubKey = new byte[]{10, 20, 30};

        when(repository.countActiveByUserId(userId)).thenReturn(0);

        PasskeyCredential cred = service.enrollPasskey(userId, credId, pubKey, 0, "internal", "TouchID");

        assertThat(cred.state()).isEqualTo(PasskeyState.PENDING_ACTIVATION);
        assertThat(cred.activatesAt()).isEqualTo(baseTime.plus(Duration.ofHours(24)));
        assertThat(cred.createdAt()).isEqualTo(baseTime);

        verify(repository).insertPasskey(cred);
        verify(applicationEventPublisher).publishEvent(any(PasskeyEnrolled.class));
        verify(securityEventPublisher).publish(eq("PASSKEY_ENROLLED"), eq("passkey"), any(), any());
    }

    @Test
    @DisplayName("AC-002 / AF-01 / BR-002: Passkey adicional cuando ya existe uno activo queda ACTIVE de inmediato")
    void enrollSubsequentPasskeyEntersActiveImmediately() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{5, 6, 7, 8};
        byte[] pubKey = new byte[]{40, 50, 60};

        when(repository.countActiveByUserId(userId)).thenReturn(1);

        PasskeyCredential cred = service.enrollPasskey(userId, credId, pubKey, 0, "usb", "YubiKey 5");

        assertThat(cred.state()).isEqualTo(PasskeyState.ACTIVE);
        assertThat(cred.activatesAt()).isNull();

        verify(repository).insertPasskey(cred);
        verify(applicationEventPublisher).publishEvent(any(PasskeyEnrolled.class));
        verify(applicationEventPublisher).publishEvent(any(PasskeyActivated.class));
        verify(securityEventPublisher).publish(eq("PASSKEY_ACTIVATED"), eq("passkey"), any(), any());
    }

    @Test
    @DisplayName("AC-003 / AF-02: Intentar activar un passkey en cuarentena antes de 24 horas es rechazado")
    void activatePendingPasskeyFailsBefore24Hours() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};
        Instant activatesAt = baseTime.plus(Duration.ofHours(24));

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, credId, new byte[]{1}, 0, "internal", "TouchID",
                PasskeyState.PENDING_ACTIVATION, activatesAt, baseTime, null
        );

        when(repository.findByCredentialId(credId)).thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.activatePendingPasskey(userId, credId))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("período de cuarentena de 24 horas");

        verify(repository, never()).updateState(any(), any());
    }

    @Test
    @DisplayName("AC-004: Passkey en cuarentena cuyo plazo de 24h ya transcurrió puede ser activado")
    void activatePendingPasskeySucceedsAfter24Hours() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};
        // activatesAt was 1 hour ago
        Instant activatesAt = baseTime.minus(Duration.ofHours(1));

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, credId, new byte[]{1}, 0, "internal", "TouchID",
                PasskeyState.PENDING_ACTIVATION, activatesAt, baseTime.minus(Duration.ofHours(25)), null
        );

        when(repository.findByCredentialId(credId)).thenReturn(Optional.of(cred));

        service.activatePendingPasskey(userId, credId);

        verify(repository).updateState(credId, PasskeyState.ACTIVE);
        verify(applicationEventPublisher).publishEvent(any(PasskeyActivated.class));
        verify(securityEventPublisher).publish(eq("PASSKEY_ACTIVATED"), eq("passkey"), any(), any());
    }

    @Test
    @DisplayName("AC-005 / AF-03 / BR-003: Aserción con contador menor o igual al registrado detecta clonación")
    void assertionWithDecreasingSignCountDetectsClone() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, credId, new byte[]{1}, 100, "internal", "TouchID",
                PasskeyState.ACTIVE, null, baseTime.minus(Duration.ofDays(2)), baseTime.minus(Duration.ofHours(1))
        );

        when(repository.findByCredentialId(credId)).thenReturn(Optional.of(cred));

        // Authenticator reported 95 (less than 100) -> CLONE!
        AssertionResult result = service.verifyAssertion(credId, 95);

        assertThat(result).isEqualTo(AssertionResult.ANOMALY_DETECTED);
        verify(applicationEventPublisher).publishEvent(any(PasskeyCounterAnomaly.class));
        verify(securityEventPublisher).publish(eq("PASSKEY_COUNTER_ANOMALY"), eq("passkey"), any(), any());
        verify(repository, never()).updateSignCountAndLastUsed(any(), anyLong(), any());
    }

    @Test
    @DisplayName("BR-003: Aserción con contador 0 constante permite passkeys sincronizados (iCloud Keychain, Google Password Manager)")
    void assertionWithZeroSignCountAllowsSyncAuthenticators() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, credId, new byte[]{1}, 0, "internal", "iCloud Passkey",
                PasskeyState.ACTIVE, null, baseTime.minus(Duration.ofDays(2)), baseTime.minus(Duration.ofHours(1))
        );

        when(repository.findByCredentialId(credId)).thenReturn(Optional.of(cred));

        AssertionResult result = service.verifyAssertion(credId, 0);

        assertThat(result).isEqualTo(AssertionResult.SUCCESS);
        verify(repository).updateSignCountAndLastUsed(credId, 0, baseTime);
    }

    @Test
    @DisplayName("BR-003: Aserción con contador incremental normal actualiza la credencial exitosamente")
    void assertionWithAdvancingSignCountSucceeds() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, credId, new byte[]{1}, 100, "usb", "YubiKey",
                PasskeyState.ACTIVE, null, baseTime.minus(Duration.ofDays(2)), baseTime.minus(Duration.ofHours(1))
        );

        when(repository.findByCredentialId(credId)).thenReturn(Optional.of(cred));

        AssertionResult result = service.verifyAssertion(credId, 101);

        assertThat(result).isEqualTo(AssertionResult.SUCCESS);
        verify(repository).updateSignCountAndLastUsed(credId, 101, baseTime);
    }

    @Test
    @DisplayName("AC-006 / AF-04: Revocación de un passkey marca su estado REVOKED e impide su uso")
    void revokePasskeyMarksRevoked() {
        UUID userId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, credId, new byte[]{1}, 10, "usb", "Old Key",
                PasskeyState.ACTIVE, null, baseTime.minus(Duration.ofDays(5)), null
        );

        when(repository.findByCredentialId(credId)).thenReturn(Optional.of(cred));

        service.revokePasskey(userId, credId);

        verify(repository).updateState(credId, PasskeyState.REVOKED);
        verify(applicationEventPublisher).publishEvent(any(PasskeyRevoked.class));
        verify(securityEventPublisher).publish(eq("PASSKEY_REVOKED"), eq("passkey"), any(), any());
    }

    @Test
    @DisplayName("AC-006: Intentar revocar passkey de otro usuario lanza SecurityException")
    void revokePasskeyThrowsWhenNotOwner() {
        UUID ownerId = UUID.randomUUID();
        UUID otherUserId = UUID.randomUUID();
        byte[] credId = new byte[]{1, 2, 3, 4};

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), ownerId, credId, new byte[]{1}, 10, "usb", "Key",
                PasskeyState.ACTIVE, null, baseTime.minus(Duration.ofDays(5)), null
        );

        when(repository.findByCredentialId(credId)).thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.revokePasskey(otherUserId, credId))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("No tiene autorización");

        verify(repository, never()).updateState(any(), any());
    }
}
