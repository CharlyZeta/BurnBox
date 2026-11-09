package com.burnbox.ops;

import java.time.Instant;

public record JobRun(
        Long id,
        String jobName,
        Instant startedAt,
        Instant finishedAt,
        JobRunStatus status,
        int processedCount,
        int errorCount,
        String details
) {}
