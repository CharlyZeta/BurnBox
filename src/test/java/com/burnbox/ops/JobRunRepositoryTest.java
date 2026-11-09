package com.burnbox.ops;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class JobRunRepositoryTest {

    private final Instant start = Instant.parse("2026-11-09T17:00:00Z");
    private final Instant end = Instant.parse("2026-11-09T17:00:05Z");

    @SuppressWarnings("unchecked")
    private ObjectProvider<JdbcClient> providerOf(JdbcClient client) {
        ObjectProvider<JdbcClient> provider = Mockito.mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    @Test
    @DisplayName("AC-006 & BR-005: JobRunRepository persiste el registro de auditoría en job_run")
    void recordsJobRunInDatabase() {
        JdbcClient jdbcClient = Mockito.mock(JdbcClient.class);
        JdbcClient.StatementSpec spec = Mockito.mock(JdbcClient.StatementSpec.class);

        when(jdbcClient.sql(anyString())).thenReturn(spec);
        when(spec.param(anyString(), any())).thenReturn(spec);
        when(spec.update()).thenReturn(1);

        JobRunRepository repository = new JobRunRepository(providerOf(jdbcClient));

        repository.record(
                "expired-secret-purge",
                start,
                end,
                JobRunStatus.SUCCESS,
                10,
                0,
                "{\"processed\":10}"
        );

        verify(jdbcClient).sql(contains("INSERT INTO job_run"));
        verify(spec).param("jobName", "expired-secret-purge");
        verify(spec).param("status", "SUCCESS");
        verify(spec).param("processedCount", 10);
        verify(spec).param("errorCount", 0);
        verify(spec).update();
    }

    @Test
    @DisplayName("AF-02: Si JdbcClient no está disponible, JobRunRepository degrada a no-op sin lanzar excepción")
    void noOpWhenJdbcClientNotAvailable() {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcClient> emptyProvider = Mockito.mock(ObjectProvider.class);
        when(emptyProvider.getIfAvailable()).thenReturn(null);

        JobRunRepository repository = new JobRunRepository(emptyProvider);

        assertThatNoException().isThrownBy(() ->
                repository.record("tombstone-cleanup", start, end, JobRunStatus.SUCCESS, 0, 0, "{}")
        );
    }
}
