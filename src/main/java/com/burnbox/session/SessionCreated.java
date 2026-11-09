package com.burnbox.session;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record SessionCreated(
        String sessionId,
        UUID userId,
        Instant createdAt
) {
    public SessionCreated {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
    }
}
