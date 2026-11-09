package com.burnbox.identity;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record UserLoggedIn(
        UUID userId,
        IdentityProvider provider,
        Instant occurredAt
) {
    public UserLoggedIn {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(occurredAt, "occurredAt must not be null");
    }
}
