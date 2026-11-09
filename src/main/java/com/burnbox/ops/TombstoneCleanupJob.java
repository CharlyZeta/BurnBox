package com.burnbox.ops;

import com.burnbox.secret.SecretRepository;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Daily background job to permanently delete terminal secret records (tombstones)
 * older than the 30-day retention grace period (BR-004, C-17).
 */
@Component
public class TombstoneCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(TombstoneCleanupJob.class);
    public static final String JOB_NAME = "tombstone-cleanup";
    private static final int BATCH_SIZE = 500;
    private static final Duration RETENTION_PERIOD = Duration.ofDays(30);

    private final SecretRepository secretRepository;
    private final JobRunRepository jobRunRepository;
    private final Clock clock;

    public TombstoneCleanupJob(
            SecretRepository secretRepository,
            JobRunRepository jobRunRepository,
            Clock clock
    ) {
        this.secretRepository = secretRepository;
        this.jobRunRepository = jobRunRepository;
        this.clock = clock;
    }

    @Scheduled(cron = "${burnbox.jobs.tombstone-cleanup.cron:0 0 3 * * *}")
    @SchedulerLock(name = JOB_NAME, lockAtMostFor = "PT30M", lockAtLeastFor = "PT2S")
    @ConditionalOnProperty(name = "burnbox.scheduler.enabled", havingValue = "true", matchIfMissing = true)
    public void schedule() {
        run();
    }

    public int run() {
        Instant startedAt = Instant.now(clock);
        Instant olderThan = startedAt.minus(RETENTION_PERIOD);
        int totalDeleted = 0;
        int errorCount = 0;

        try {
            int deletedInBatch;
            do {
                deletedInBatch = secretRepository.deleteTombstones(olderThan, BATCH_SIZE);
                totalDeleted += deletedInBatch;
            } while (deletedInBatch >= BATCH_SIZE);

            Instant finishedAt = Instant.now(clock);
            JobRunStatus status = JobRunStatus.SUCCESS;
            jobRunRepository.record(JOB_NAME, startedAt, finishedAt, status, totalDeleted, errorCount, "{\"deleted\":" + totalDeleted + "}");

            log.info("Finished job {} with status {}, deleted={}", JOB_NAME, status, totalDeleted);
            return totalDeleted;
        } catch (Exception e) {
            Instant finishedAt = Instant.now(clock);
            jobRunRepository.record(JOB_NAME, startedAt, finishedAt, JobRunStatus.FAILED, totalDeleted, errorCount + 1, "{\"error\":\"" + e.getMessage() + "\"}");
            log.error("Job {} failed with unexpected error", JOB_NAME, e);
            return totalDeleted;
        }
    }
}
