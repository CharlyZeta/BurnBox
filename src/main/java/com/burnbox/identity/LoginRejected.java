package com.burnbox.identity;

import java.time.Instant;
import java.util.Objects;

public record LoginRejected(
        IdentityProvider provider,
        String reason,
        Instant occurredAt
) {
    public LoginRejected {
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(occurredAt, "occurredAt must not be null");
    }
}
