package com.burnbox.identity;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record LinkedIdentity(
        UUID id,
        UUID userId,
        IdentityProvider provider,
        String issuer,
        String subject,
        String emailAtLink,
        boolean emailVerifiedAtLink,
        Instant createdAt,
        Instant lastUsedAt
) {
    public LinkedIdentity {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
    }
}
