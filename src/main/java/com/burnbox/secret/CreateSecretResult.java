package com.burnbox.secret;

import java.time.Instant;
import java.util.UUID;

public record CreateSecretResult(
        UUID secretId,
        String rawToken,
        String tokenHash,
        Instant expiresAt
) {}
