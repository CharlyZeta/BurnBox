package com.burnbox.notification;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

@Repository
public class NotificationRepository {

    private final ObjectProvider<JdbcClient> jdbcClientProvider;

    public NotificationRepository(ObjectProvider<JdbcClient> jdbcClientProvider) {
        this.jdbcClientProvider = jdbcClientProvider;
    }

    private JdbcClient jdbc() {
        JdbcClient client = jdbcClientProvider.getIfAvailable();
        if (client == null) {
            throw new IllegalStateException("JdbcClient is not available");
        }
        return client;
    }

    public void insertNotification(NotificationDelivery delivery) {
        jdbc().sql("""
                INSERT INTO notification_delivery (
                    id, source_event_id, user_id, template, recipient_email, channel, status, attempts, next_attempt_at, last_error, created_at, sent_at
                ) VALUES (
                    :id, :sourceEventId, :userId, :template, :recipientEmail, :channel, :status, :attempts, :nextAttemptAt, :lastError, :createdAt, :sentAt
                )
                """)
                .param("id", delivery.id())
                .param("sourceEventId", delivery.sourceEventId())
                .param("userId", delivery.userId())
                .param("template", delivery.template())
                .param("recipientEmail", delivery.recipientEmail())
                .param("channel", delivery.channel())
                .param("status", delivery.status().name())
                .param("attempts", delivery.attempts())
                .param("nextAttemptAt", delivery.nextAttemptAt() != null ? OffsetDateTime.ofInstant(delivery.nextAttemptAt(), ZoneOffset.UTC) : null)
                .param("lastError", delivery.lastError())
                .param("createdAt", OffsetDateTime.ofInstant(delivery.createdAt(), ZoneOffset.UTC))
                .param("sentAt", delivery.sentAt() != null ? OffsetDateTime.ofInstant(delivery.sentAt(), ZoneOffset.UTC) : null)
                .update();
    }

    public Optional<NotificationDelivery> findBySourceTemplateAndUser(String sourceEventId, String template, UUID userId) {
        return jdbc().sql("""
                SELECT id, source_event_id, user_id, template, recipient_email, channel, status, attempts, next_attempt_at, last_error, created_at, sent_at
                FROM notification_delivery
                WHERE source_event_id = :sourceEventId AND template = :template AND user_id = :userId
                """)
                .param("sourceEventId", sourceEventId)
                .param("template", template)
                .param("userId", userId)
                .query((rs, rowNum) -> new NotificationDelivery(
                        (UUID) rs.getObject("id"),
                        rs.getString("source_event_id"),
                        (UUID) rs.getObject("user_id"),
                        rs.getString("template"),
                        rs.getString("recipient_email"),
                        rs.getString("channel"),
                        NotificationStatus.valueOf(rs.getString("status")),
                        rs.getInt("attempts"),
                        toInstant(rs.getTimestamp("next_attempt_at")),
                        rs.getString("last_error"),
                        toInstant(rs.getTimestamp("created_at")),
                        toInstant(rs.getTimestamp("sent_at"))
                ))
                .optional();
    }

    public void updateStatusSent(UUID id, Instant sentAt) {
        jdbc().sql("""
                UPDATE notification_delivery
                SET status = 'SENT', sent_at = :sentAt
                WHERE id = :id
                """)
                .param("id", id)
                .param("sentAt", OffsetDateTime.ofInstant(sentAt, ZoneOffset.UTC))
                .update();
    }

    public void updateStatusFailed(UUID id, int attempts, Instant nextAttemptAt, String lastError) {
        jdbc().sql("""
                UPDATE notification_delivery
                SET status = 'FAILED', attempts = :attempts, next_attempt_at = :nextAttemptAt, last_error = :lastError
                WHERE id = :id
                """)
                .param("id", id)
                .param("attempts", attempts)
                .param("nextAttemptAt", nextAttemptAt != null ? OffsetDateTime.ofInstant(nextAttemptAt, ZoneOffset.UTC) : null)
                .param("lastError", lastError)
                .update();
    }

    public void updateStatusDead(UUID id, int attempts, String lastError) {
        jdbc().sql("""
                UPDATE notification_delivery
                SET status = 'DEAD', attempts = :attempts, last_error = :lastError
                WHERE id = :id
                """)
                .param("id", id)
                .param("attempts", attempts)
                .param("lastError", lastError)
                .update();
    }

    private static Instant toInstant(Timestamp ts) {
        return ts != null ? ts.toInstant() : null;
    }
}
