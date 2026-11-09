package com.burnbox.ops;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

@Repository
public class JobRunRepository {

    private final ObjectProvider<JdbcClient> jdbcClientProvider;

    public JobRunRepository(ObjectProvider<JdbcClient> jdbcClientProvider) {
        this.jdbcClientProvider = jdbcClientProvider;
    }

    public void record(String jobName, Instant startedAt, Instant finishedAt, JobRunStatus status, int processedCount, int errorCount, String details) {
        JdbcClient client = jdbcClientProvider.getIfAvailable();
        if (client == null) {
            return;
        }

        client.sql("""
                INSERT INTO job_run (job_name, started_at, finished_at, status, processed_count, error_count, details)
                VALUES (:jobName, :startedAt, :finishedAt, :status, :processedCount, :errorCount, :details::jsonb)
                """)
                .param("jobName", jobName)
                .param("startedAt", Timestamp.from(startedAt))
                .param("finishedAt", Timestamp.from(finishedAt))
                .param("status", status.name())
                .param("processedCount", processedCount)
                .param("errorCount", errorCount)
                .param("details", (details != null && !details.isBlank()) ? details : "{}")
                .update();
    }

    public List<JobRun> findLatestRuns(int limit) {
        JdbcClient client = jdbcClientProvider.getIfAvailable();
        if (client == null) {
            return Collections.emptyList();
        }

        return client.sql("""
                SELECT id, job_name, started_at, finished_at, status, processed_count, error_count, details::text as details
                FROM job_run
                ORDER BY started_at DESC, id DESC
                LIMIT :limit
                """)
                .param("limit", limit)
                .query((rs, rowNum) -> new JobRun(
                        rs.getLong("id"),
                        rs.getString("job_name"),
                        rs.getTimestamp("started_at").toInstant(),
                        rs.getTimestamp("finished_at").toInstant(),
                        JobRunStatus.valueOf(rs.getString("status")),
                        rs.getInt("processed_count"),
                        rs.getInt("error_count"),
                        rs.getString("details")
                ))
                .list();
    }
}
