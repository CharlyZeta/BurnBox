package com.burnbox.notification;

import com.burnbox.identity.AppUser;
import com.burnbox.identity.UserRepository;
import com.burnbox.platform.SecurityEventPublisher;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class NotificationService {

    public static final int MAX_ATTEMPTS = 5;

    private final NotificationRepository repository;
    private final UserRepository userRepository;
    private final EmailSenderClient emailSenderClient;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final SecurityEventPublisher securityEventPublisher;
    private final Clock clock;

    public NotificationService(
            NotificationRepository repository,
            UserRepository userRepository,
            EmailSenderClient emailSenderClient,
            ApplicationEventPublisher applicationEventPublisher,
            SecurityEventPublisher securityEventPublisher,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.emailSenderClient = Objects.requireNonNull(emailSenderClient, "emailSenderClient must not be null");
        this.applicationEventPublisher = Objects.requireNonNull(applicationEventPublisher, "applicationEventPublisher must not be null");
        this.securityEventPublisher = Objects.requireNonNull(securityEventPublisher, "securityEventPublisher must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Transactional
    public Optional<NotificationDelivery> dispatchNotification(
            String sourceEventId,
            UUID userId,
            String template,
            String subject,
            String body
    ) {
        Objects.requireNonNull(sourceEventId, "sourceEventId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(template, "template must not be null");
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(body, "body must not be null");

        Instant now = Instant.now(clock);

        // BR-001 / AF-01: Only send to users with verified primary email
        Optional<AppUser> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return Optional.empty();
        }

        AppUser user = userOpt.get();
        if (user.primaryEmail() == null || user.primaryEmail().isBlank() || !user.primaryEmailVerified()) {
            return Optional.empty();
        }

        // BR-003 / AF-02: Idempotency check
        Optional<NotificationDelivery> existing = repository.findBySourceTemplateAndUser(sourceEventId, template, userId);
        if (existing.isPresent()) {
            return existing;
        }

        UUID notificationId = UUID.randomUUID();
        NotificationDelivery delivery = new NotificationDelivery(
                notificationId,
                sourceEventId,
                userId,
                template,
                user.primaryEmail(),
                "EMAIL",
                NotificationStatus.PENDING,
                0,
                null,
                null,
                now,
                null
        );

        repository.insertNotification(delivery);

        applicationEventPublisher.publishEvent(new NotificationQueued(
                notificationId, sourceEventId, userId, template, user.primaryEmail(), now
        ));
        securityEventPublisher.publish("NOTIFICATION_QUEUED", "notification", notificationId.toString(), Map.of(
                "userId", userId.toString(),
                "template", template
        ));

        // Attempt dispatch
        try {
            emailSenderClient.send(user.primaryEmail(), subject, body);

            repository.updateStatusSent(notificationId, now);

            applicationEventPublisher.publishEvent(new NotificationSent(
                    notificationId, userId, template, user.primaryEmail(), now
            ));
            securityEventPublisher.publish("NOTIFICATION_SENT", "notification", notificationId.toString(), Map.of(
                    "userId", userId.toString(),
                    "template", template
            ));

            return Optional.of(new NotificationDelivery(
                    notificationId, sourceEventId, userId, template, user.primaryEmail(), "EMAIL",
                    NotificationStatus.SENT, 1, null, null, now, now
            ));
        } catch (Exception ex) {
            int attempts = 1;
            String errorMsg = ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();

            if (attempts >= MAX_ATTEMPTS) {
                repository.updateStatusDead(notificationId, attempts, errorMsg);
                applicationEventPublisher.publishEvent(new NotificationDead(
                        notificationId, userId, template, attempts, errorMsg, now
                ));
                securityEventPublisher.publish("NOTIFICATION_DEAD", "notification", notificationId.toString(), Map.of(
                        "userId", userId.toString(),
                        "template", template,
                        "attempts", String.valueOf(attempts)
                ));
            } else {
                Instant nextRetry = now.plus(Duration.ofMinutes(1));
                repository.updateStatusFailed(notificationId, attempts, nextRetry, errorMsg);
                applicationEventPublisher.publishEvent(new NotificationFailed(
                        notificationId, userId, template, attempts, errorMsg, now
                ));
                securityEventPublisher.publish("NOTIFICATION_FAILED", "notification", notificationId.toString(), Map.of(
                        "userId", userId.toString(),
                        "template", template,
                        "attempts", String.valueOf(attempts)
                ));
            }

            return Optional.of(new NotificationDelivery(
                    notificationId, sourceEventId, userId, template, user.primaryEmail(), "EMAIL",
                    attempts >= MAX_ATTEMPTS ? NotificationStatus.DEAD : NotificationStatus.FAILED,
                    attempts, now.plus(Duration.ofMinutes(1)), errorMsg, now, null
            ));
        }
    }

    @Transactional
    public void retryNotification(NotificationDelivery delivery, int nextAttemptNumber, String subject, String body) {
        Instant now = Instant.now(clock);

        try {
            emailSenderClient.send(delivery.recipientEmail(), subject, body);
            repository.updateStatusSent(delivery.id(), now);
            applicationEventPublisher.publishEvent(new NotificationSent(
                    delivery.id(), delivery.userId(), delivery.template(), delivery.recipientEmail(), now
            ));
        } catch (Exception ex) {
            String errorMsg = ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();

            if (nextAttemptNumber >= MAX_ATTEMPTS) {
                repository.updateStatusDead(delivery.id(), nextAttemptNumber, errorMsg);
                applicationEventPublisher.publishEvent(new NotificationDead(
                        delivery.id(), delivery.userId(), delivery.template(), nextAttemptNumber, errorMsg, now
                ));
            } else {
                Instant nextRetry = now.plus(Duration.ofMinutes(5));
                repository.updateStatusFailed(delivery.id(), nextAttemptNumber, nextRetry, errorMsg);
                applicationEventPublisher.publishEvent(new NotificationFailed(
                        delivery.id(), delivery.userId(), delivery.template(), nextAttemptNumber, errorMsg, now
                ));
            }
        }
    }
}
