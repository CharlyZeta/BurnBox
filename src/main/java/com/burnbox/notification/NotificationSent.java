package com.burnbox.notification;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record NotificationSent(
        UUID notificationId,
        UUID userId,
        String template,
        String recipientEmail,
        Instant sentAt
) {
    public NotificationSent {
        Objects.requireNonNull(notificationId, "notificationId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(template, "template must not be null");
        Objects.requireNonNull(recipientEmail, "recipientEmail must not be null");
        Objects.requireNonNull(sentAt, "sentAt must not be null");
    }
}
