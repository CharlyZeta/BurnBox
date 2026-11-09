package com.burnbox.secret;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain entity representing an ephemeral secret.
 * Enforces BR-001, BR-002, BR-003 invariants.
 */
public record Secret(
        UUID id,
        UUID ownerUserId,
        String tokenHash,
        byte[] ciphertext,
        byte[] nonce,
        byte[] wrappedDek,
        int keyVersion,
        int formatVersion,
        byte[] passphraseSalt,
        boolean passphraseProtected,
        int maxViews,
        int views,
        SecretState state,
        Instant expiresAt,
        Instant createdAt,
        Instant consumedAt,
        int failedAttempts,
        String recipientEmail,
        String label
) {
    public Secret {
        if (id == null) {
            throw new IllegalArgumentException("id cannot be null");
        }
        if (tokenHash == null || tokenHash.isBlank()) {
            throw new IllegalArgumentException("tokenHash cannot be null or blank");
        }
        if (state == null) {
            throw new IllegalArgumentException("state cannot be null");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt cannot be null");
        }
        if (createdAt == null) {
            throw new IllegalArgumentException("createdAt cannot be null");
        }
        if (views > maxViews) {
            throw new IllegalStateException("Invariant violated: views (" + views + ") > maxViews (" + maxViews + ")");
        }
        if (state.isTerminal() && (ciphertext != null || wrappedDek != null)) {
            throw new IllegalStateException("Invariant violated: sensitive content must be null in terminal state " + state);
        }
    }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public boolean canBeRevealed(Instant now) {
        return state == SecretState.ACTIVE && !isExpired(now) && views < maxViews;
    }
}
