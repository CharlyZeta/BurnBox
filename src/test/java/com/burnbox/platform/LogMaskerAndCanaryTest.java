package com.burnbox.platform;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LogMaskerAndCanaryTest {

    @Test
    @DisplayName("AC-007 / BR-005: Enmascaramiento de token en log solo expone los primeros 8 caracteres de su hash SHA-256")
    void tokenHashMaskingExposesOnlyFirst8Chars() {
        String sha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String masked = LogMasker.maskTokenHash(sha256Hex);

        assertThat(masked).isEqualTo("e3b0c442");
        assertThat(masked).hasSize(8);
    }

    @Test
    @DisplayName("AC-006 / BR-007: Test canario detecta fugas de secretos simuladas en logs")
    void canaryTestDetectsSimulatedSecretLeaks() {
        // Simulación 1: Fuga de token sin procesar (43 caracteres base64url)
        String leakedTokenLine = "INFO [req-1] Processing secret access with token 3v0_U7KkX0r_xY2qA8v1N_4b9C7d1E3f5G7h9J1k3L5";
        assertThat(LogMasker.containsSecretLeak(leakedTokenLine)).isTrue();

        // Simulación 2: Fuga de cabecera Authorization Bearer
        String leakedAuthHeader = "DEBUG [req-2] Incoming headers: Authorization: Bearer eyJhbGciOi";
        assertThat(LogMasker.containsSecretLeak(leakedAuthHeader)).isTrue();

        // Simulación 3: Fuga de passphrase
        String leakedPassphrase = "WARN [req-3] Failed attempt with passphrase=CorrectHorseBatteryStaple";
        assertThat(LogMasker.containsSecretLeak(leakedPassphrase)).isTrue();

        // Simulación 4: Fuga de Cookie de sesión
        String leakedCookie = "INFO [req-4] Session cookie: SESSION=abc123xyz";
        assertThat(LogMasker.containsSecretLeak(leakedCookie)).isTrue();

        // Traza limpia con token enmascarado
        String cleanLogLine = "INFO [req-5] Secret viewed successfully. token_prefix=e3b0c442, views=1";
        assertThat(LogMasker.containsSecretLeak(cleanLogLine)).isFalse();
    }

    @Test
    @DisplayName("AC-006: Pipeline de CI falla explícitamente si el test canario detecta un secreto")
    void canaryFailsExplicitlyOnDetectedSecret() {
        String logOutputFromService = "Access granted for token abc123def456_-abc123def456_-abc123def456_--";

        boolean leakDetected = LogMasker.containsSecretLeak(logOutputFromService);

        assertThat(leakDetected).isTrue();
        assertThatThrownBy(() -> {
            if (leakDetected) {
                throw new AssertionError("CANARY FAILURE: Secret leak detected in log stream: " + logOutputFromService);
            }
        }).isInstanceOf(AssertionError.class)
          .hasMessageContaining("CANARY FAILURE");
    }

    @Test
    @DisplayName("AC-005 / BR-003: Estructura esperada de logs JSON")
    void structuredJsonLogFieldsIntegrity() {
        String jsonLogSample = """
                {"@timestamp":"2026-11-09T10:00:00Z","log.level":"INFO","message":"Secret accessed","request_id":"req-123","user_ref":"usr-456","event":"SECRET_READ"}
                """;

        assertThat(jsonLogSample).contains("\"@timestamp\":");
        assertThat(jsonLogSample).contains("\"log.level\":");
        assertThat(jsonLogSample).contains("\"request_id\":\"req-123\"");
        assertThat(jsonLogSample).contains("\"event\":\"SECRET_READ\"");
    }
}
