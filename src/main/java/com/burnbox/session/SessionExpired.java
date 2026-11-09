package com.burnbox.session;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record SessionExpired(
        String sessionId,
        UUID userId,
        Instant expiredAt,
        String reason
) {
    public SessionExpired {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(expiredAt, "expiredAt must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
    }
}
