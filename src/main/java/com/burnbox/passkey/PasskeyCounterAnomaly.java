package com.burnbox.passkey;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record PasskeyCounterAnomaly(
        byte[] credentialId,
        UUID userId,
        long previousCount,
        long reportedCount,
        Instant detectedAt
) {
    public PasskeyCounterAnomaly {
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(detectedAt, "detectedAt must not be null");
    }
}
