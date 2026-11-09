package com.burnbox.ratelimit;

import java.time.Instant;
import java.util.Objects;

/**
 * Domain event emitted when an IP subnet / prefix exhibits abusive behavior
 * (such as 10 failed token attempts within 5 minutes).
 * Strictly contains NO unhashed tokens, plaintext secrets, or PII.
 */
public record AbuseIpFlagged(
        String ipPrefix,
        Instant flaggedAt,
        String reason
) {
    public AbuseIpFlagged {
        Objects.requireNonNull(ipPrefix, "ipPrefix must not be null");
        Objects.requireNonNull(flaggedAt, "flaggedAt must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
    }
}
