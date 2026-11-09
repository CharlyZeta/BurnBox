package com.burnbox.ops;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Health indicator for background hygiene and maintenance jobs (C-22, C-23).
 * Reports DOWN if any of the recent job runs failed (BR-004, BR-005).
 */
@Component("jobs")
public class JobRunHealthIndicator implements HealthIndicator {

    private final JobRunRepository jobRunRepository;

    public JobRunHealthIndicator(JobRunRepository jobRunRepository) {
        this.jobRunRepository = jobRunRepository;
    }

    @Override
    public Health health() {
        try {
            List<JobRun> latestRuns = jobRunRepository.findLatestRuns(5);
            for (JobRun run : latestRuns) {
                if (run.status() == JobRunStatus.FAILED) {
                    return Health.down()
                            .withDetail("failed_job", run.jobName())
                            .withDetail("failed_at", run.startedAt().toString())
                            .withDetail("error_count", run.errorCount())
                            .build();
                }
            }

            return Health.up()
                    .withDetail("recent_runs_count", latestRuns.size())
                    .build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
