package com.burnbox.ops;

import com.burnbox.crypto.KeyProvider;
import com.burnbox.platform.SecurityEventPublisher;
import com.burnbox.secret.SecretRepository;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Background job to re-envelope DEKs of active secrets encrypted with an older KEK version (C-19).
 * Operates in batches with SKIP LOCKED. Does not access, decrypt, or modify ciphertext or nonce (BR-001).
 * Immediately zeroes transient DEK byte array in memory (BR-002).
 */
@Component
public class KeyReEnvelopeJob {

    private static final Logger log = LoggerFactory.getLogger(KeyReEnvelopeJob.class);
    public static final String JOB_NAME = "key-re-envelope";
    private static final int BATCH_SIZE = 500;

    private final SecretRepository secretRepository;
    private final KeyProvider keyProvider;
    private final JobRunRepository jobRunRepository;
    private final SecurityEventPublisher securityEventPublisher;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Value("${burnbox.scheduler.enabled:true}")
    private boolean schedulerEnabled = true;

    public KeyReEnvelopeJob(
            SecretRepository secretRepository,
            KeyProvider keyProvider,
            JobRunRepository jobRunRepository,
            SecurityEventPublisher securityEventPublisher,
            Clock clock
    ) {
        this.secretRepository = secretRepository;
        this.keyProvider = keyProvider;
        this.jobRunRepository = jobRunRepository;
        this.securityEventPublisher = securityEventPublisher;
        this.clock = clock;
    }

    @Scheduled(cron = "${burnbox.jobs.key-re-envelope.cron:0 */30 * * * *}")
    @SchedulerLock(name = JOB_NAME, lockAtMostFor = "PT30M", lockAtLeastFor = "PT5S")
    public void schedule() {
        if (!schedulerEnabled) {
            return;
        }
        run();
    }

    public int run() {
        Instant startedAt = Instant.now(clock);
        int targetVersion = keyProvider.getActiveVersion();
        int totalReEnveloped = 0;
        int errorCount = 0;

        try {
            List<SecretRepository.PendingReEnvelopeRecord> batch;
            do {
                batch = secretRepository.findSecretsPendingReEnvelope(targetVersion, BATCH_SIZE);
                for (SecretRepository.PendingReEnvelopeRecord record : batch) {
                    byte[] dek = null;
                    try {
                        dek = keyProvider.unwrap(record.wrappedDek(), record.keyVersion());
                        byte[] newWrappedDek = keyProvider.wrap(dek, targetVersion);
                        secretRepository.updateReEnvelopedSecret(record.id(), newWrappedDek, targetVersion);
                        totalReEnveloped++;
                    } catch (Exception e) {
                        errorCount++;
                        log.error("Failed to re-envelope secret id={}", record.id(), e);
                    } finally {
                        if (dek != null) {
                            Arrays.fill(dek, (byte) 0);
                        }
                    }
                }
            } while (!batch.isEmpty());

            Instant finishedAt = Instant.now(clock);
            JobRunStatus status = (errorCount == 0) ? JobRunStatus.SUCCESS : JobRunStatus.PARTIAL;

            if (totalReEnveloped > 0) {
                securityEventPublisher.publish(
                        "KEK_ROTATION_COMPLETED",
                        "key",
                        String.valueOf(targetVersion),
                        Map.of("re_enveloped_count", totalReEnveloped)
                );
            }

            jobRunRepository.record(
                    JOB_NAME,
                    startedAt,
                    finishedAt,
                    status,
                    totalReEnveloped,
                    errorCount,
                    "{\"targetVersion\":" + targetVersion + ",\"reEnveloped\":" + totalReEnveloped + "}"
            );

            log.info("Finished job {} for targetVersion={}, reEnveloped={}, errors={}", JOB_NAME, targetVersion, totalReEnveloped, errorCount);
            return totalReEnveloped;
        } catch (Exception e) {
            Instant finishedAt = Instant.now(clock);
            jobRunRepository.record(
                    JOB_NAME,
                    startedAt,
                    finishedAt,
                    JobRunStatus.FAILED,
                    totalReEnveloped,
                    errorCount + 1,
                    "{\"error\":\"" + e.getMessage() + "\"}"
            );
            log.error("Job {} failed with unexpected error", JOB_NAME, e);
            return totalReEnveloped;
        }
    }
}
