package com.burnbox.secret;

import java.time.Duration;
import java.util.UUID;
import java.util.regex.Pattern;

public record CreateSecretCommand(
        byte[] plaintext,
        Duration ttl,
        int maxViews,
        UUID ownerUserId,
        String recipientEmail,
        String label,
        String passphrase
) {
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    public CreateSecretCommand(
            byte[] plaintext,
            Duration ttl,
            int maxViews,
            UUID ownerUserId,
            String recipientEmail,
            String label
    ) {
        this(plaintext, ttl, maxViews, ownerUserId, recipientEmail, label, null);
    }

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
        if (passphrase != null && !passphrase.isBlank()) {
            if (passphrase.length() < 8 || passphrase.length() > 128) {
                throw new IllegalArgumentException("Passphrase must be between 8 and 128 characters");
            }
        }
        if (recipientEmail != null && !recipientEmail.isBlank()) {
            String trimmed = recipientEmail.trim();
            if (trimmed.length() > 255 || !EMAIL_PATTERN.matcher(trimmed).matches()) {
                throw new IllegalArgumentException("Invalid recipient email format: " + recipientEmail);
            }
            recipientEmail = trimmed.toLowerCase();
        } else {
            recipientEmail = null;
        }
    }
}
