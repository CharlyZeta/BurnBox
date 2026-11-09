package com.burnbox.ops;

import com.burnbox.crypto.KeyProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyHealthIndicatorTest {

    @Test
    @DisplayName("AC-001, BR-001 & BR-003: Reporta UP con versión activa sin exponer material criptográfico")
    void reportsUpWhenActiveKeyAvailable() {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getActiveVersion()).thenReturn(2);

        KeyHealthIndicator indicator = new KeyHealthIndicator(keyProvider);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("active_version", 2);
        assertThat(health.getDetails()).doesNotContainKey("kek");
        assertThat(health.getDetails()).doesNotContainKey("key");
        assertThat(health.getDetails()).doesNotContainKey("bytes");
    }

    @Test
    @DisplayName("AC-002 & AF-01: Reporta DOWN si no existe KEK activa configurada")
    void reportsDownWhenNoActiveKey() {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getActiveVersion()).thenReturn(0);

        KeyHealthIndicator indicator = new KeyHealthIndicator(keyProvider);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "No active KEK configured");
    }

    @Test
    @DisplayName("BR-005 & AC-008: Captura excepciones internas y degrada a DOWN limpiamente")
    void handlesProviderExceptionGracefully() {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getActiveVersion()).thenThrow(new RuntimeException("KMS connection refused"));

        KeyHealthIndicator indicator = new KeyHealthIndicator(keyProvider);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsKey("error");
    }
}
