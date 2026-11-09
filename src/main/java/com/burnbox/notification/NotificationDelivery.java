package com.burnbox.notification;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record NotificationDelivery(
        UUID id,
        String sourceEventId,
        UUID userId,
        String template,
        String recipientEmail,
        String channel,
        NotificationStatus status,
        int attempts,
        Instant nextAttemptAt,
        String lastError,
        Instant createdAt,
        Instant sentAt
) {
    public NotificationDelivery {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(sourceEventId, "sourceEventId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(template, "template must not be null");
        Objects.requireNonNull(recipientEmail, "recipientEmail must not be null");
        Objects.requireNonNull(channel, "channel must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
    }
}
