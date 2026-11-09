package com.burnbox.audit;

import java.time.Instant;
import java.util.UUID;

public record SecurityEventRecord(
        Long id,
        Instant occurredAt,
        String eventType,
        UUID actorUserId,
        String subjectType,
        String subjectId,
        String requestId,
        String ipHash,
        String details,
        String prevHash,
        String hash
) {
    public String truncatedHash() {
        if (hash == null || hash.length() < 16) {
            return (hash != null) ? hash : "N/A";
        }
        return hash.substring(0, 16) + "...";
    }
}
