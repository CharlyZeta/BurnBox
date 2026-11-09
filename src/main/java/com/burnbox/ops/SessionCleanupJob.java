package com.burnbox.ops;

import com.burnbox.session.UserSessionRepository;
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
 * Scheduled job to purge expired and revoked user sessions (C-17).
 * Removes sessions idle for >30m or older than 12h absolute.
 */
@Component
public class SessionCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(SessionCleanupJob.class);
    public static final String JOB_NAME = "session-cleanup";
    private static final Duration INACTIVITY_WINDOW = Duration.ofMinutes(30);
    private static final Duration ABSOLUTE_WINDOW = Duration.ofHours(12);

    private final UserSessionRepository userSessionRepository;
    private final JobRunRepository jobRunRepository;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Value("${burnbox.scheduler.enabled:true}")
    private boolean schedulerEnabled = true;

    public SessionCleanupJob(
            UserSessionRepository userSessionRepository,
            JobRunRepository jobRunRepository,
            Clock clock
    ) {
        this.userSessionRepository = userSessionRepository;
        this.jobRunRepository = jobRunRepository;
        this.clock = clock;
    }

    @Scheduled(cron = "${burnbox.jobs.session-cleanup.cron:0 */15 * * * *}")
    @SchedulerLock(name = JOB_NAME, lockAtMostFor = "PT10M", lockAtLeastFor = "PT2S")
    public void schedule() {
        if (!schedulerEnabled) {
            return;
        }
        run();
    }

    public int run() {
        Instant startedAt = Instant.now(clock);
        Instant inactiveThreshold = startedAt.minus(INACTIVITY_WINDOW);
        Instant absoluteThreshold = startedAt.minus(ABSOLUTE_WINDOW);
        int totalDeleted = 0;
        int errorCount = 0;

        try {
            totalDeleted = userSessionRepository.deleteExpiredSessions(inactiveThreshold, absoluteThreshold);

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
