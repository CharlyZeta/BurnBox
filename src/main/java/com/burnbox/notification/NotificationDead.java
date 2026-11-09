package com.burnbox.notification;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record NotificationDead(
        UUID notificationId,
        UUID userId,
        String template,
        int totalAttempts,
        String finalError,
        Instant deadAt
) {
    public NotificationDead {
        Objects.requireNonNull(notificationId, "notificationId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(template, "template must not be null");
        Objects.requireNonNull(finalError, "finalError must not be null");
        Objects.requireNonNull(deadAt, "deadAt must not be null");
    }
}
