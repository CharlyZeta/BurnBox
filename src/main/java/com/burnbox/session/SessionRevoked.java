package com.burnbox.session;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record SessionRevoked(
        String sessionId,
        UUID userId,
        Instant revokedAt,
        String reason
) {
    public SessionRevoked {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(revokedAt, "revokedAt must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
    }
}
