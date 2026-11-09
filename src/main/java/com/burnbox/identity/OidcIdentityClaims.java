package com.burnbox.identity;

import java.util.Objects;

public record OidcIdentityClaims(
        IdentityProvider provider,
        String issuer,
        String subject,
        String email,
        boolean emailVerified,
        String displayName,
        String locale
) {
    public OidcIdentityClaims {
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(subject, "subject must not be null");
    }
}
