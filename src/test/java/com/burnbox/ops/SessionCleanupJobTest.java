package com.burnbox.ops;

import com.burnbox.session.UserSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class SessionCleanupJobTest {

    private UserSessionRepository userSessionRepository;
    private JobRunRepository jobRunRepository;
    private Clock clock;
    private SessionCleanupJob job;

    private final Instant fixedTime = Instant.parse("2026-11-09T17:00:00Z");

    @BeforeEach
    void setUp() {
        userSessionRepository = mock(UserSessionRepository.class);
        jobRunRepository = mock(JobRunRepository.class);
        clock = Clock.fixed(fixedTime, ZoneOffset.UTC);

        job = new SessionCleanupJob(userSessionRepository, jobRunRepository, clock);
    }

    @Test
    @DisplayName("AC-005, BR-005 & BR-006: Elimina sesiones vencidas con umbrales de inactividad (30m) y obsolescencia (12h)")
    void deletesExpiredSessionsCorrectly() {
        Instant expectedInactive = fixedTime.minus(Duration.ofMinutes(30));
        Instant expectedAbsolute = fixedTime.minus(Duration.ofHours(12));

        when(userSessionRepository.deleteExpiredSessions(eq(expectedInactive), eq(expectedAbsolute)))
                .thenReturn(15);

        int totalDeleted = job.run();

        assertThat(totalDeleted).isEqualTo(15);
        verify(userSessionRepository).deleteExpiredSessions(eq(expectedInactive), eq(expectedAbsolute));
        verify(jobRunRepository).record(
                eq(SessionCleanupJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(15),
                eq(0),
                contains("\"deleted\":15")
        );
    }

    @Test
    @DisplayName("AC-008 & BR-001: Ejecución manual repetida es idempotente")
    void manualInvocationIsIdempotent() {
        when(userSessionRepository.deleteExpiredSessions(any(), any()))
                .thenReturn(0);

        int firstRun = job.run();
        int secondRun = job.run();

        assertThat(firstRun).isEqualTo(0);
        assertThat(secondRun).isEqualTo(0);
        verify(jobRunRepository, times(2)).record(
                eq(SessionCleanupJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(0),
                eq(0),
                any()
        );
    }

    @Test
    @DisplayName("AF-02: Error en repositorio se registra en job_run sin provocar crash")
    void handlesRepositoryFailureGracefully() {
        when(userSessionRepository.deleteExpiredSessions(any(), any()))
                .thenThrow(new RuntimeException("Lock wait timeout"));

        int totalDeleted = job.run();

        assertThat(totalDeleted).isEqualTo(0);
        verify(jobRunRepository).record(
                eq(SessionCleanupJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.FAILED),
                eq(0),
                eq(1),
                contains("Lock wait timeout")
        );
    }
}
