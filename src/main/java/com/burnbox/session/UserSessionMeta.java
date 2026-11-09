package com.burnbox.session;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record UserSessionMeta(
        UUID id,
        String sessionId,
        UUID userId,
        String ipHash,
        String userAgentSummary,
        Instant createdAt,
        Instant lastAccessedAt,
        boolean revoked
) {
    public UserSessionMeta {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(ipHash, "ipHash must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(lastAccessedAt, "lastAccessedAt must not be null");
    }
}
