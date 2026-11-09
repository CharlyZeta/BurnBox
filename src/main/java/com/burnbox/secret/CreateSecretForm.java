package com.burnbox.secret;

import java.time.Duration;

public record CreateSecretForm(
        String content,
        String ttl,
        Integer maxViews,
        String passphrase
) {
    public CreateSecretForm(String content, String ttl, Integer maxViews) {
        this(content, ttl, maxViews, null);
    }

    public CreateSecretForm {
        if (ttl == null || ttl.isBlank()) {
            ttl = "1h";
        }
        if (maxViews == null) {
            maxViews = 1;
        }
    }

    public Duration parseTtl() {
        return switch (ttl.trim().toLowerCase()) {
            case "5m" -> Duration.ofMinutes(5);
            case "1h" -> Duration.ofHours(1);
            case "1d" -> Duration.ofDays(1);
            case "7d" -> Duration.ofDays(7);
            default -> throw new IllegalArgumentException("TTL inválido: " + ttl);
        };
    }
}
