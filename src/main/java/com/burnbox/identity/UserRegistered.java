package com.burnbox.identity;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record UserRegistered(
        UUID userId,
        IdentityProvider provider,
        String issuer,
        String subject,
        Instant occurredAt
) {
    public UserRegistered {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(occurredAt, "occurredAt must not be null");
    }
}
