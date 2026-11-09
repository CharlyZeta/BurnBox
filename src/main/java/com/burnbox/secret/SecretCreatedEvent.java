package com.burnbox.secret;

import java.time.Instant;
import java.util.UUID;

public record SecretCreatedEvent(
        UUID secretId,
        String tokenHash,
        Instant expiresAt,
        int maxViews
) {}
