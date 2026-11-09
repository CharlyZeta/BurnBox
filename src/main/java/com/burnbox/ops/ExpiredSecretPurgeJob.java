package com.burnbox.ops;

import com.burnbox.platform.SecurityEventPublisher;
import com.burnbox.secret.SecretExpiredEvent;
import com.burnbox.secret.SecretRepository;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Background job to purge expired active secrets every minute (C-17).
 * Atomically marks them as EXPIRED and blanks all sensitive payload columns with SKIP LOCKED.
 */
@Component
public class ExpiredSecretPurgeJob {

    private static final Logger log = LoggerFactory.getLogger(ExpiredSecretPurgeJob.class);
    public static final String JOB_NAME = "expired-secret-purge";
    private static final int BATCH_SIZE = 500;

    private final SecretRepository secretRepository;
    private final JobRunRepository jobRunRepository;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final SecurityEventPublisher securityEventPublisher;
    private final Clock clock;

    public ExpiredSecretPurgeJob(
            SecretRepository secretRepository,
            JobRunRepository jobRunRepository,
            ApplicationEventPublisher applicationEventPublisher,
            SecurityEventPublisher securityEventPublisher,
            Clock clock
    ) {
        this.secretRepository = secretRepository;
        this.jobRunRepository = jobRunRepository;
        this.applicationEventPublisher = applicationEventPublisher;
        this.securityEventPublisher = securityEventPublisher;
        this.clock = clock;
    }

    @Scheduled(cron = "${burnbox.jobs.expired-secret-purge.cron:0 * * * * *}")
    @SchedulerLock(name = JOB_NAME, lockAtMostFor = "PT2M", lockAtLeastFor = "PT2S")
    @ConditionalOnProperty(name = "burnbox.scheduler.enabled", havingValue = "true", matchIfMissing = true)
    public void schedule() {
        run();
    }

    public int run() {
        Instant startedAt = Instant.now(clock);
        int totalProcessed = 0;
        int errorCount = 0;

        try {
            List<SecretRepository.ExpiredSecretRecord> batch;
            do {
                batch = secretRepository.purgeExpiredSecrets(startedAt, BATCH_SIZE);
                for (SecretRepository.ExpiredSecretRecord item : batch) {
                    try {
                        applicationEventPublisher.publishEvent(new SecretExpiredEvent(item.id(), item.tokenHash(), startedAt));
                        securityEventPublisher.publish("SECRET_EXPIRED", "secret", item.id().toString(), Map.of());
                        totalProcessed++;
                    } catch (Exception e) {
                        errorCount++;
                        log.error("Failed to publish expiration event for secret id={}", item.id(), e);
                    }
                }
            } while (!batch.isEmpty());

            Instant finishedAt = Instant.now(clock);
            JobRunStatus status = (errorCount == 0) ? JobRunStatus.SUCCESS : JobRunStatus.PARTIAL;
            jobRunRepository.record(JOB_NAME, startedAt, finishedAt, status, totalProcessed, errorCount, "{\"processed\":" + totalProcessed + "}");

            log.info("Finished job {} with status {}, processed={}, errors={}", JOB_NAME, status, totalProcessed, errorCount);
            return totalProcessed;
        } catch (Exception e) {
            Instant finishedAt = Instant.now(clock);
            jobRunRepository.record(JOB_NAME, startedAt, finishedAt, JobRunStatus.FAILED, totalProcessed, errorCount + 1, "{\"error\":\"" + e.getMessage() + "\"}");
            log.error("Job {} failed with unexpected error", JOB_NAME, e);
            return totalProcessed;
        }
    }
}
