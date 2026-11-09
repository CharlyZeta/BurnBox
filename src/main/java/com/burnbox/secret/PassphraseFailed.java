package com.burnbox.secret;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Domain event published when an invalid passphrase attempt occurs.
 * Strictly avoids logging or storing plaintext passphrases.
 */
public record PassphraseFailed(
        UUID secretId,
        int failedAttempts,
        int remainingAttempts,
        Instant occurredAt
) {
    public PassphraseFailed {
        Objects.requireNonNull(secretId, "secretId must not be null");
        Objects.requireNonNull(occurredAt, "occurredAt must not be null");
    }
}
