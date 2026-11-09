package com.burnbox.ops;

import com.burnbox.crypto.KeyProvider;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Health indicator for the cryptographic Key Encryption Key (KEK) ring (C-22, C-23).
 * Verifies that an active KEK version is available without ever exposing raw key bytes (BR-001, BR-003).
 */
@Component("key")
public class KeyHealthIndicator implements HealthIndicator {

    private final KeyProvider keyProvider;

    public KeyHealthIndicator(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    public Health health() {
        try {
            int activeVersion = keyProvider.getActiveVersion();
            if (activeVersion > 0) {
                return Health.up()
                        .withDetail("active_version", activeVersion)
                        .build();
            } else {
                return Health.down()
                        .withDetail("reason", "No active KEK configured")
                        .build();
            }
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
