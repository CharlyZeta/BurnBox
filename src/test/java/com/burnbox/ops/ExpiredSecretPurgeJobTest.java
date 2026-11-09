package com.burnbox.ops;

import com.burnbox.platform.SecurityEventPublisher;
import com.burnbox.secret.SecretExpiredEvent;
import com.burnbox.secret.SecretRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class ExpiredSecretPurgeJobTest {

    private SecretRepository secretRepository;
    private JobRunRepository jobRunRepository;
    private ApplicationEventPublisher eventPublisher;
    private SecurityEventPublisher securityEventPublisher;
    private Clock clock;
    private ExpiredSecretPurgeJob job;

    private final Instant fixedTime = Instant.parse("2026-11-09T17:00:00Z");

    @BeforeEach
    void setUp() {
        secretRepository = mock(SecretRepository.class);
        jobRunRepository = mock(JobRunRepository.class);
        eventPublisher = mock(ApplicationEventPublisher.class);
        securityEventPublisher = mock(SecurityEventPublisher.class);
        clock = Clock.fixed(fixedTime, ZoneOffset.UTC);

        job = new ExpiredSecretPurgeJob(
                secretRepository,
                jobRunRepository,
                eventPublisher,
                securityEventPublisher,
                clock
        );
    }

    @Test
    @DisplayName("AC-001 & BR-003: Purga secretos vencidos, emite eventos y registra ejecución exitosa en job_run")
    void purgesExpiredSecretsAndEmitsEvents() {
        UUID secretId1 = UUID.randomUUID();
        UUID secretId2 = UUID.randomUUID();

        List<SecretRepository.ExpiredSecretRecord> batch1 = List.of(
                new SecretRepository.ExpiredSecretRecord(secretId1, "hash1"),
                new SecretRepository.ExpiredSecretRecord(secretId2, "hash2")
        );

        when(secretRepository.purgeExpiredSecrets(eq(fixedTime), eq(500)))
                .thenReturn(batch1)
                .thenReturn(Collections.emptyList());

        int processed = job.run();

        assertThat(processed).isEqualTo(2);

        verify(eventPublisher, times(2)).publishEvent(any(SecretExpiredEvent.class));
        verify(securityEventPublisher).publish(eq("SECRET_EXPIRED"), eq("secret"), eq(secretId1.toString()), any());
        verify(securityEventPublisher).publish(eq("SECRET_EXPIRED"), eq("secret"), eq(secretId2.toString()), any());

        verify(jobRunRepository).record(
                eq(ExpiredSecretPurgeJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(2),
                eq(0),
                contains("\"processed\":2")
        );
    }

    @Test
    @DisplayName("AC-002: Si no hay secretos activos vencidos, no realiza cambios ni emite eventos")
    void doesNothingWhenNoExpiredSecrets() {
        when(secretRepository.purgeExpiredSecrets(eq(fixedTime), eq(500)))
                .thenReturn(Collections.emptyList());

        int processed = job.run();

        assertThat(processed).isEqualTo(0);
        verifyNoInteractions(eventPublisher);
        verifyNoInteractions(securityEventPublisher);
        verify(jobRunRepository).record(
                eq(ExpiredSecretPurgeJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(0),
                eq(0),
                contains("\"processed\":0")
        );
    }

    @Test
    @DisplayName("AF-02: Fallo en publicación de evento marca PARTIAL y no detiene la ejecución")
    void handlesEventPublicationErrorGracefully() {
        UUID secretId = UUID.randomUUID();
        List<SecretRepository.ExpiredSecretRecord> batch = List.of(
                new SecretRepository.ExpiredSecretRecord(secretId, "hash1")
        );

        when(secretRepository.purgeExpiredSecrets(eq(fixedTime), eq(500)))
                .thenReturn(batch)
                .thenReturn(Collections.emptyList());

        doThrow(new RuntimeException("Kafka error"))
                .when(securityEventPublisher).publish(any(), any(), any(), any());

        int processed = job.run();

        assertThat(processed).isEqualTo(0);
        verify(jobRunRepository).record(
                eq(ExpiredSecretPurgeJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.PARTIAL),
                eq(0),
                eq(1),
                any()
        );
    }

    @Test
    @DisplayName("BR-001 & AF-04: Idempotencia y ejecución manual directa en perfil de prueba")
    void manualInvocationIsIdempotent() {
        when(secretRepository.purgeExpiredSecrets(eq(fixedTime), eq(500)))
                .thenReturn(Collections.emptyList());

        int firstRun = job.run();
        int secondRun = job.run();

        assertThat(firstRun).isEqualTo(0);
        assertThat(secondRun).isEqualTo(0);
        verify(jobRunRepository, times(2)).record(any(), any(), any(), eq(JobRunStatus.SUCCESS), eq(0), eq(0), any());
    }
}
