package com.burnbox.passkey;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record PasskeyActivated(
        byte[] credentialId,
        UUID userId,
        Instant activatedAt
) {
    public PasskeyActivated {
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(activatedAt, "activatedAt must not be null");
    }
}
