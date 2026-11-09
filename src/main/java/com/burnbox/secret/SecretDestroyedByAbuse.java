package com.burnbox.secret;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Domain event published when a secret is permanently destroyed after 5 failed passphrase attempts.
 */
public record SecretDestroyedByAbuse(
        UUID secretId,
        Instant destroyedAt,
        String reason
) {
    public SecretDestroyedByAbuse {
        Objects.requireNonNull(secretId, "secretId must not be null");
        Objects.requireNonNull(destroyedAt, "destroyedAt must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
    }
}
