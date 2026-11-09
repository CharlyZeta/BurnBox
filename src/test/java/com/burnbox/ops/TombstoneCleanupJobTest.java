package com.burnbox.ops;

import com.burnbox.secret.SecretRepository;
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

class TombstoneCleanupJobTest {

    private SecretRepository secretRepository;
    private JobRunRepository jobRunRepository;
    private Clock clock;
    private TombstoneCleanupJob job;

    private final Instant fixedTime = Instant.parse("2026-11-09T17:00:00Z");

    @BeforeEach
    void setUp() {
        secretRepository = mock(SecretRepository.class);
        jobRunRepository = mock(JobRunRepository.class);
        clock = Clock.fixed(fixedTime, ZoneOffset.UTC);

        job = new TombstoneCleanupJob(secretRepository, jobRunRepository, clock);
    }

    @Test
    @DisplayName("AC-003, BR-004 & BR-006: Elimina lápidas terminales con más de 30 días de antigüedad usando Clock")
    void deletesTombstonesOlderThan30Days() {
        Instant expectedThreshold = fixedTime.minus(Duration.ofDays(30));

        when(secretRepository.deleteTombstones(eq(expectedThreshold), eq(500)))
                .thenReturn(500)
                .thenReturn(42);

        int totalDeleted = job.run();

        assertThat(totalDeleted).isEqualTo(542);

        verify(secretRepository, times(2)).deleteTombstones(eq(expectedThreshold), eq(500));
        verify(jobRunRepository).record(
                eq(TombstoneCleanupJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(542),
                eq(0),
                contains("\"deleted\":542")
        );
    }

    @Test
    @DisplayName("AC-004 & AF-03: Si no hay lápidas con más de 30 días, retorna 0 y no borra nada")
    void preservesRecentTombstonesAndActiveSecrets() {
        Instant expectedThreshold = fixedTime.minus(Duration.ofDays(30));

        when(secretRepository.deleteTombstones(eq(expectedThreshold), eq(500)))
                .thenReturn(0);

        int totalDeleted = job.run();

        assertThat(totalDeleted).isEqualTo(0);
        verify(jobRunRepository).record(
                eq(TombstoneCleanupJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(0),
                eq(0),
                contains("\"deleted\":0")
        );
    }

    @Test
    @DisplayName("AF-02: Maneja fallos inesperados registrando FAILED en job_run sin lanzar excepción")
    void handlesRepositoryFailureGracefully() {
        when(secretRepository.deleteTombstones(any(), anyInt()))
                .thenThrow(new RuntimeException("DB connection error"));

        int totalDeleted = job.run();

        assertThat(totalDeleted).isEqualTo(0);
        verify(jobRunRepository).record(
                eq(TombstoneCleanupJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.FAILED),
                eq(0),
                eq(1),
                contains("DB connection error")
        );
    }
}
