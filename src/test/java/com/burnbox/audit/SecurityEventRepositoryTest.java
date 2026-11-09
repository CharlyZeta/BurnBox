package com.burnbox.audit;

import com.burnbox.platform.SecurityEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class SecurityEventRepositoryTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private ObjectProvider<JdbcClient> providerOf(JdbcClient client) {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcClient> provider = Mockito.mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    @Test
    @DisplayName("AC-003 / AF-02: Detalles vacíos se persisten como objeto JSON {}")
    void savesEventWithEmptyDetailsAsEmptyJsonObject() {
        JdbcClient jdbcClient = Mockito.mock(JdbcClient.class);
        JdbcClient.StatementSpec spec = Mockito.mock(JdbcClient.StatementSpec.class);

        when(jdbcClient.sql(anyString())).thenReturn(spec);
        when(spec.param(anyString(), any())).thenReturn(spec);
        when(spec.update()).thenReturn(1);

        SecurityEventRepository repository = new SecurityEventRepository(providerOf(jdbcClient), objectMapper);

        SecurityEvent event = new SecurityEvent(
                "SECRET_READ",
                Instant.parse("2026-11-09T10:00:00Z"),
                UUID.randomUUID().toString(),
                "req-1",
                "ip-hash-1",
                "secret",
                "sec-1",
                Map.of()
        );

        assertThatCode(() -> repository.save(event)).doesNotThrowAnyException();
        Mockito.verify(spec).param("details", "{}");
    }

    @Test
    @DisplayName("AF-03: Falla de persistencia en base de datos no interrumpe el flujo del invocador")
    void persistenceFailureDoesNotThrow() {
        JdbcClient jdbcClient = Mockito.mock(JdbcClient.class);
        when(jdbcClient.sql(anyString())).thenThrow(new DataIntegrityViolationException("Simulated DB connection failure"));

        SecurityEventRepository repository = new SecurityEventRepository(providerOf(jdbcClient), objectMapper);

        SecurityEvent event = new SecurityEvent(
                "SECRET_BURNED",
                Instant.parse("2026-11-09T10:00:00Z"),
                null,
                "req-fail",
                "ip-fail",
                null,
                null,
                null
        );

        // Debe capturar la excepción y registrarla en logs técnicos sin lanzar error
        assertThatCode(() -> repository.save(event)).doesNotThrowAnyException();
    }
}
