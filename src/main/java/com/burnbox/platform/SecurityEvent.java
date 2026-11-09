package com.burnbox.platform;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

/**
 * Domain record representing an immutable security audit event.
 * Prohibits PII and sensitive secret content in details.
 */
public record SecurityEvent(
        String eventType,
        Instant occurredAt,
        String actorUserId,
        String requestId,
        String ipHash,
        String subjectType,
        String subjectId,
        Map<String, Object> details
) {
    public SecurityEvent {
        if (eventType == null || eventType.isBlank()) {
            throw new IllegalArgumentException("eventType cannot be null or blank");
        }
        if (occurredAt == null) {
            throw new IllegalArgumentException("occurredAt cannot be null");
        }
        if (requestId == null || requestId.isBlank()) {
            requestId = "system";
        }
        if (ipHash == null || ipHash.isBlank()) {
            ipHash = "unknown";
        }
        details = (details == null) ? Map.of() : Collections.unmodifiableMap(details);
    }

    public static SecurityEvent of(
            String eventType,
            Instant occurredAt,
            String actorUserId,
            String requestId,
            String ipHash,
            Map<String, Object> details
    ) {
        return new SecurityEvent(eventType, occurredAt, actorUserId, requestId, ipHash, null, null, details);
    }
}
