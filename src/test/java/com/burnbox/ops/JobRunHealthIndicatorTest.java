package com.burnbox.ops;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JobRunHealthIndicatorTest {

    private final Instant now = Instant.parse("2026-11-09T17:00:00Z");

    @Test
    @DisplayName("AC-003 & BR-004: Reporta UP cuando no hay ejecuciones o las recientes fueron exitosas")
    void reportsUpWhenRunsSuccessful() {
        JobRunRepository repository = mock(JobRunRepository.class);
        JobRun run1 = new JobRun(1L, "expired-secret-purge", now, now, JobRunStatus.SUCCESS, 10, 0, "{}");
        JobRun run2 = new JobRun(2L, "tombstone-cleanup", now, now, JobRunStatus.SUCCESS, 5, 0, "{}");

        when(repository.findLatestRuns(anyInt())).thenReturn(List.of(run1, run2));

        JobRunHealthIndicator indicator = new JobRunHealthIndicator(repository);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("recent_runs_count", 2);
    }

    @Test
    @DisplayName("AC-004 & AF-02: Reporta DOWN cuando el último run de un job falló")
    void reportsDownWhenRecentRunFailed() {
        JobRunRepository repository = mock(JobRunRepository.class);
        JobRun failed = new JobRun(1L, "key-re-envelope", now, now, JobRunStatus.FAILED, 0, 1, "{\"error\":\"fail\"}");

        when(repository.findLatestRuns(anyInt())).thenReturn(List.of(failed));

        JobRunHealthIndicator indicator = new JobRunHealthIndicator(repository);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("failed_job", "key-re-envelope");
        assertThat(health.getDetails()).containsEntry("error_count", 1);
    }

    @Test
    @DisplayName("BR-005 & AC-008: Error al consultar BD retorna DOWN limpiamente")
    void handlesDatabaseExceptionGracefully() {
        JobRunRepository repository = mock(JobRunRepository.class);
        when(repository.findLatestRuns(anyInt())).thenThrow(new RuntimeException("DB unavailable"));

        JobRunHealthIndicator indicator = new JobRunHealthIndicator(repository);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsKey("error");
    }
}
