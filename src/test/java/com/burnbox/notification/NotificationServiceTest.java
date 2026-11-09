package com.burnbox.notification;

import com.burnbox.identity.AppUser;
import com.burnbox.identity.UserRepository;
import com.burnbox.identity.UserStatus;
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
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationServiceTest {

    @Mock
    private NotificationRepository repository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailSenderClient emailSenderClient;

    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    @Mock
    private SecurityEventPublisher securityEventPublisher;

    private Clock clock;
    private NotificationService service;
    private final Instant baseTime = Instant.parse("2026-11-09T16:00:00Z");

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(baseTime, ZoneOffset.UTC);
        service = new NotificationService(
                repository,
                userRepository,
                emailSenderClient,
                applicationEventPublisher,
                securityEventPublisher,
                clock
        );
    }

    @Test
    @DisplayName("AC-001 / AC-005 / BR-001: Despacha email a usuario con email verificado y actualiza estado a SENT")
    void dispatchesEmailToVerifiedUser() throws Exception {
        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser(
                userId, "Alice", "alice@example.com", true,
                UserStatus.ACTIVE, null, "es", baseTime, baseTime
        );

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(repository.findBySourceTemplateAndUser("event-100", "secret-consumed", userId)).thenReturn(Optional.empty());

        Optional<NotificationDelivery> result = service.dispatchNotification(
                "event-100",
                userId,
                "secret-consumed",
                "Tu secreto ha sido revelado",
                "El secreto con identificador abc12... fue revelado el 2026-11-09."
        );

        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo(NotificationStatus.SENT);
        assertThat(result.get().recipientEmail()).isEqualTo("alice@example.com");

        verify(emailSenderClient).send(eq("alice@example.com"), contains("revelado"), contains("abc12"));
        verify(repository).updateStatusSent(result.get().id(), baseTime);
        verify(applicationEventPublisher).publishEvent(any(NotificationSent.class));
        verify(securityEventPublisher).publish(eq("NOTIFICATION_SENT"), eq("notification"), any(), any());
    }

    @Test
    @DisplayName("AC-002 / AF-01 / BR-001: No envía notificación a usuario con email no verificado")
    void skipsDispatchForUnverifiedEmail() throws Exception {
        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser(
                userId, "Bob", "bob@example.com", false, // Unverified!
                UserStatus.ACTIVE, null, "es", baseTime, baseTime
        );

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        Optional<NotificationDelivery> result = service.dispatchNotification(
                "event-101",
                userId,
                "secret-consumed",
                "Aviso",
                "Cuerpo del mensaje"
        );

        assertThat(result).isEmpty();
        verify(emailSenderClient, never()).send(any(), any(), any());
        verify(repository, never()).insertNotification(any());
    }

    @Test
    @DisplayName("AC-003 / AF-02 / BR-003: Idempotencia evita envíos duplicados ante el mismo sourceEventId")
    void idempotentDispatchIgnoresDuplicates() throws Exception {
        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser(
                userId, "Carol", "carol@example.com", true,
                UserStatus.ACTIVE, null, "es", baseTime, baseTime
        );

        NotificationDelivery existing = new NotificationDelivery(
                UUID.randomUUID(), "event-duplicate", userId, "secret-consumed",
                "carol@example.com", "EMAIL", NotificationStatus.SENT, 1, null, null, baseTime, baseTime
        );

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(repository.findBySourceTemplateAndUser("event-duplicate", "secret-consumed", userId))
                .thenReturn(Optional.of(existing));

        Optional<NotificationDelivery> result = service.dispatchNotification(
                "event-duplicate",
                userId,
                "secret-consumed",
                "Asunto",
                "Cuerpo"
        );

        assertThat(result).contains(existing);
        verify(emailSenderClient, never()).send(any(), any(), any());
    }

    @Test
    @DisplayName("AC-004 / BR-002: El cuerpo del correo no incluye contraseñas ni tokens sensibles")
    void bodyExcludesSecretAndTokens() throws Exception {
        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser(
                userId, "Dan", "dan@example.com", true,
                UserStatus.ACTIVE, null, "es", baseTime, baseTime
        );

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(repository.findBySourceTemplateAndUser("event-sec", "secret-consumed", userId)).thenReturn(Optional.empty());

        String subject = "Burnbox: Secreto consumido";
        String body = "El secreto con ID sec-999 fue consumido a las 16:00 UTC.";

        service.dispatchNotification("event-sec", userId, "secret-consumed", subject, body);

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSenderClient).send(any(), any(), bodyCaptor.capture());

        assertThat(bodyCaptor.getValue())
                .doesNotContain("Bearer")
                .doesNotContain("token_hash")
                .doesNotContain("password")
                .doesNotContain("ciphertext");
    }

    @Test
    @DisplayName("AC-006 / AF-03 / BR-004: Falla de envío transiciona a FAILED y programa reintento")
    void failedSendUpdatesToFailedWithRetryScheduled() throws Exception {
        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser(
                userId, "Eve", "eve@example.com", true,
                UserStatus.ACTIVE, null, "es", baseTime, baseTime
        );

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(repository.findBySourceTemplateAndUser("event-fail", "passkey-enrolled", userId)).thenReturn(Optional.empty());
        doThrow(new RuntimeException("SMTP connection refused")).when(emailSenderClient).send(any(), any(), any());

        Optional<NotificationDelivery> result = service.dispatchNotification(
                "event-fail",
                userId,
                "passkey-enrolled",
                "Nueva passkey enrolada",
                "Se ha agregado TouchID a tu cuenta"
        );

        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo(NotificationStatus.FAILED);
        assertThat(result.get().attempts()).isEqualTo(1);

        verify(repository).updateStatusFailed(eq(result.get().id()), eq(1), any(), contains("SMTP connection refused"));
        verify(applicationEventPublisher).publishEvent(any(NotificationFailed.class));
    }

    @Test
    @DisplayName("AC-007 / AF-04 / BR-004: Quinto fallo consecutivo transiciona a estado DEAD")
    void fifthFailureTransitionsToDead() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID notificationId = UUID.randomUUID();

        NotificationDelivery delivery = new NotificationDelivery(
                notificationId, "event-dead", userId, "secret-destroyed",
                "target@example.com", "EMAIL", NotificationStatus.FAILED, 4, baseTime, "Previous error", baseTime, null
        );

        doThrow(new RuntimeException("Mail server permanently down")).when(emailSenderClient).send(any(), any(), any());

        service.retryNotification(delivery, 5, "Destrucción de secreto", "Aviso de destrucción");

        verify(repository).updateStatusDead(eq(notificationId), eq(5), contains("permanently down"));
        verify(applicationEventPublisher).publishEvent(any(NotificationDead.class));
    }
}
