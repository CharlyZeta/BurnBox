package com.burnbox.notification;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record NotificationQueued(
        UUID notificationId,
        String sourceEventId,
        UUID userId,
        String template,
        String recipientEmail,
        Instant queuedAt
) {
    public NotificationQueued {
        Objects.requireNonNull(notificationId, "notificationId must not be null");
        Objects.requireNonNull(sourceEventId, "sourceEventId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(template, "template must not be null");
        Objects.requireNonNull(recipientEmail, "recipientEmail must not be null");
        Objects.requireNonNull(queuedAt, "queuedAt must not be null");
    }
}
