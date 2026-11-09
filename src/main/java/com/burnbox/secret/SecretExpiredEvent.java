package com.burnbox.secret;

import java.time.Instant;
import java.util.UUID;

public record SecretExpiredEvent(
        UUID secretId,
        String tokenHash,
        Instant expiredAt
) {}
