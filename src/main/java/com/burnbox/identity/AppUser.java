package com.burnbox.identity;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record AppUser(
        UUID id,
        String displayName,
        String primaryEmail,
        boolean primaryEmailVerified,
        UserStatus status,
        Instant deletionScheduledAt,
        String locale,
        Instant createdAt,
        Instant lastLoginAt
) {
    public AppUser {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        if (locale == null || locale.isBlank()) {
            locale = "es";
        }
        if (status == UserStatus.PENDING_DELETION && deletionScheduledAt == null) {
            throw new IllegalStateException("deletionScheduledAt is required for PENDING_DELETION status");
        }
    }
}
