package com.burnbox.ops;

import com.burnbox.crypto.KeyProvider;
import com.burnbox.platform.SecurityEventPublisher;
import com.burnbox.secret.SecretRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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

class KeyReEnvelopeJobTest {

    private SecretRepository secretRepository;
    private KeyProvider keyProvider;
    private JobRunRepository jobRunRepository;
    private SecurityEventPublisher securityEventPublisher;
    private Clock clock;
    private KeyReEnvelopeJob job;

    private final Instant fixedTime = Instant.parse("2026-11-09T17:00:00Z");

    @BeforeEach
    void setUp() {
        secretRepository = mock(SecretRepository.class);
        keyProvider = mock(KeyProvider.class);
        jobRunRepository = mock(JobRunRepository.class);
        securityEventPublisher = mock(SecurityEventPublisher.class);
        clock = Clock.fixed(fixedTime, ZoneOffset.UTC);

        job = new KeyReEnvelopeJob(
                secretRepository,
                keyProvider,
                jobRunRepository,
                securityEventPublisher,
                clock
        );
    }

    @Test
    @DisplayName("AC-001, AC-005, BR-001, BR-002: Re-envuelve DEK a nueva versión activa de KEK sin alterar payload y vaciando memoria")
    void reEnvelopesSecretsToActiveVersion() {
        when(keyProvider.getActiveVersion()).thenReturn(2);

        UUID secretId = UUID.randomUUID();
        byte[] oldWrappedDek = new byte[]{0x11, 0x22};
        byte[] rawDek = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[] newWrappedDek = new byte[]{0x33, 0x44};

        SecretRepository.PendingReEnvelopeRecord record =
                new SecretRepository.PendingReEnvelopeRecord(secretId, oldWrappedDek, 1);

        when(secretRepository.findSecretsPendingReEnvelope(eq(2), eq(500)))
                .thenReturn(List.of(record))
                .thenReturn(Collections.emptyList());

        when(keyProvider.unwrap(eq(oldWrappedDek), eq(1))).thenReturn(rawDek.clone());
        when(keyProvider.wrap(any(), eq(2))).thenReturn(newWrappedDek);

        int processed = job.run();

        assertThat(processed).isEqualTo(1);

        verify(secretRepository).updateReEnvelopedSecret(eq(secretId), eq(newWrappedDek), eq(2));
        verify(securityEventPublisher).publish(eq("KEK_ROTATION_COMPLETED"), eq("key"), eq("2"), any());
        verify(jobRunRepository).record(
                eq(KeyReEnvelopeJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(1),
                eq(0),
                contains("\"reEnveloped\":1")
        );
    }

    @Test
    @DisplayName("AC-003, AF-01 & BR-005: Si no hay secretos con versión antigua de KEK, es un no-op idempotente")
    void doesNothingWhenNoSecretsNeedReEnvelope() {
        when(keyProvider.getActiveVersion()).thenReturn(1);
        when(secretRepository.findSecretsPendingReEnvelope(eq(1), eq(500)))
                .thenReturn(Collections.emptyList());

        int processed = job.run();

        assertThat(processed).isEqualTo(0);
        verify(secretRepository, never()).updateReEnvelopedSecret(any(), any(), anyInt());
        verifyNoInteractions(securityEventPublisher);
        verify(jobRunRepository).record(
                eq(KeyReEnvelopeJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.SUCCESS),
                eq(0),
                eq(0),
                contains("\"reEnveloped\":0")
        );
    }

    @Test
    @DisplayName("AC-008 & AF-02: Fallo al desvolver un secreto corrupto registra PARTIAL y procesa los demás")
    void handlesCorruptRecordGracefully() {
        when(keyProvider.getActiveVersion()).thenReturn(2);

        UUID secretId1 = UUID.randomUUID();
        UUID secretId2 = UUID.randomUUID();

        SecretRepository.PendingReEnvelopeRecord corrupt =
                new SecretRepository.PendingReEnvelopeRecord(secretId1, new byte[]{0x00}, 1);
        SecretRepository.PendingReEnvelopeRecord valid =
                new SecretRepository.PendingReEnvelopeRecord(secretId2, new byte[]{0x01}, 1);

        when(secretRepository.findSecretsPendingReEnvelope(eq(2), eq(500)))
                .thenReturn(List.of(corrupt, valid))
                .thenReturn(Collections.emptyList());

        when(keyProvider.unwrap(eq(corrupt.wrappedDek()), eq(1)))
                .thenThrow(new RuntimeException("Decryption integrity check failed"));

        byte[] validDek = new byte[]{0x0a, 0x0b};
        when(keyProvider.unwrap(eq(valid.wrappedDek()), eq(1))).thenReturn(validDek);
        when(keyProvider.wrap(any(), eq(2))).thenReturn(new byte[]{0x0c, 0x0d});

        int processed = job.run();

        assertThat(processed).isEqualTo(1);
        verify(secretRepository).updateReEnvelopedSecret(eq(secretId2), any(), eq(2));
        verify(jobRunRepository).record(
                eq(KeyReEnvelopeJob.JOB_NAME),
                eq(fixedTime),
                eq(fixedTime),
                eq(JobRunStatus.PARTIAL),
                eq(1),
                eq(1),
                any()
        );
    }
}
