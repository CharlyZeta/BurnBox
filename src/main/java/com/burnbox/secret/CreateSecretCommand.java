package com.burnbox.secret;

import java.time.Duration;
import java.util.UUID;

public record CreateSecretCommand(
        byte[] plaintext,
        Duration ttl,
        int maxViews,
        UUID ownerUserId,
        String recipientEmail,
        String label
) {
    public CreateSecretCommand {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("plaintext cannot be null or empty");
        }
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        if (maxViews < 1) {
            throw new IllegalArgumentException("maxViews must be at least 1");
        }
    }
}
