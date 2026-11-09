package com.burnbox.passkey;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record PasskeyEnrolled(
        byte[] credentialId,
        UUID userId,
        String label,
        PasskeyState state,
        Instant activatesAt,
        Instant enrolledAt
) {
    public PasskeyEnrolled {
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(label, "label must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(enrolledAt, "enrolledAt must not be null");
    }
}
