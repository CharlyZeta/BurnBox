package com.burnbox.secret;

import java.time.Instant;
import java.util.UUID;

public record SecretConsumedEvent(
        UUID secretId,
        String tokenHash,
        Instant consumedAt
) {}
