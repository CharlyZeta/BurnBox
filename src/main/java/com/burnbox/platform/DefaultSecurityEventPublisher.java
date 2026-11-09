package com.burnbox.platform;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Default implementation of SecurityEventPublisher.
 * Enforces zero secrets and zero PII in event details (Rule 12).
 * Captures request context and injects the application Clock.
 */
@Component
public class DefaultSecurityEventPublisher implements SecurityEventPublisher {

    private static final Set<String> FORBIDDEN_DETAIL_KEYS = Set.of(
            "password",
            "passphrase",
            "token",
            "secret",
            "ciphertext",
            "cleartext",
            "plaintext",
            "authorization",
            "cookie",
            "email",
            "kek",
            "dek"
    );

    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    public DefaultSecurityEventPublisher(ApplicationEventPublisher eventPublisher, Clock clock) {
        this.eventPublisher = eventPublisher;
        this.clock = clock;
    }

    @Override
    public void publish(String eventType, Map<String, Object> details) {
        publish(eventType, null, null, details);
    }

    @Override
    public void publish(String eventType, String subjectType, String subjectId, Map<String, Object> details) {
        validateDetailsNoSecrets(details);

        Instant occurredAt = Instant.now(clock);
        String requestId = RequestContext.currentRequestId();
        String actorUserId = RequestContext.currentActor().orElse(null);
        String ipHash = RequestContext.currentIpHash().orElse("0000000000000000000000000000000000000000000000000000000000000000");

        SecurityEvent event = new SecurityEvent(
                eventType,
                occurredAt,
                actorUserId,
                requestId,
                ipHash,
                subjectType,
                subjectId,
                details
        );

        eventPublisher.publishEvent(event);
    }

    private void validateDetailsNoSecrets(Map<String, Object> details) {
        if (details == null || details.isEmpty()) {
            return;
        }

        for (Map.Entry<String, Object> entry : details.entrySet()) {
            String key = entry.getKey();
            String lowerKey = key.toLowerCase(Locale.ROOT);

            // Boolean metadata flags (e.g. passphrase_protected, password_enabled) are non-sensitive status indicators
            if (lowerKey.endsWith("_protected") || lowerKey.endsWith("_enabled") || lowerKey.endsWith("_configured")) {
                continue;
            }

            for (String forbidden : FORBIDDEN_DETAIL_KEYS) {
                if (lowerKey.contains(forbidden)) {
                    throw new IllegalArgumentException(
                            "Security event details violation: key '" + key + "' contains forbidden word '" + forbidden + "'"
                    );
                }
            }
        }
    }
}
