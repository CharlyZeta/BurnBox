package com.burnbox.passkey;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record PasskeyRevoked(
        byte[] credentialId,
        UUID userId,
        Instant revokedAt,
        String reason
) {
    public PasskeyRevoked {
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(revokedAt, "revokedAt must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
    }
}
