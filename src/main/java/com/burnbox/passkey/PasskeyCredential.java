package com.burnbox.passkey;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

public record PasskeyCredential(
        UUID id,
        UUID userId,
        byte[] credentialId,
        byte[] publicKey,
        long signCount,
        String transports,
        String label,
        PasskeyState state,
        Instant activatesAt,
        Instant createdAt,
        Instant lastUsedAt
) {
    public PasskeyCredential {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(label, "label must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        if (state == PasskeyState.PENDING_ACTIVATION && activatesAt == null) {
            throw new IllegalStateException("activatesAt is required when state is PENDING_ACTIVATION");
        }
    }

    public String credentialIdHex() {
        return HexFormat.of().formatHex(credentialId);
    }
}
