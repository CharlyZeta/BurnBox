package com.burnbox.notification;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record NotificationFailed(
        UUID notificationId,
        UUID userId,
        String template,
        int attempt,
        String error,
        Instant failedAt
) {
    public NotificationFailed {
        Objects.requireNonNull(notificationId, "notificationId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(template, "template must not be null");
        Objects.requireNonNull(error, "error must not be null");
        Objects.requireNonNull(failedAt, "failedAt must not be null");
    }
}
