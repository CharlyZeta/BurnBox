package com.burnbox.platform;

import java.util.regex.Pattern;

/**
 * Utility for sanitizing and masking sensitive tokens and detecting accidental leaks in logs.
 * Enforces BR-004 and BR-005.
 */
public final class LogMasker {

    private static final Pattern RAW_TOKEN_PATTERN = Pattern.compile("[a-zA-Z0-9_-]{43}");
    private static final Pattern SENSITIVE_KEYWORD_PATTERN = Pattern.compile(
            "(?i)(cookie|authorization:\\s*bearer|burnbox_kek|passphrase=|password=)"
    );

    private LogMasker() {
    }

    /**
     * BR-005 / AC-007: When referencing a token hash in logs, only the first 8 characters are exposed.
     */
    public static String maskTokenHash(String sha256Hex) {
        if (sha256Hex == null || sha256Hex.length() < 8) {
            return "unknown";
        }
        return sha256Hex.substring(0, 8);
    }

    /**
     * BR-007 / AC-006: Canary scanner to verify that log lines do not leak raw secrets, tokens, or credentials.
     */
    public static boolean containsSecretLeak(String logLine) {
        if (logLine == null || logLine.isBlank()) {
            return false;
        }
        if (SENSITIVE_KEYWORD_PATTERN.matcher(logLine).find()) {
            return true;
        }
        return RAW_TOKEN_PATTERN.matcher(logLine).find();
    }
}
