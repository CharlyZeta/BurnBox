package com.burnbox.audit;

import com.burnbox.platform.SecurityEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.UUID;

/**
 * Repository for storing security audit events using explicit SQL with JdbcClient.
 * Enforces AF-02 (empty JSON details if null/empty) and AF-03 (safe failure logging).
 */
@Repository
public class SecurityEventRepository {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventRepository.class);

    private final ObjectProvider<JdbcClient> jdbcClientProvider;
    private final ObjectMapper objectMapper;

    public SecurityEventRepository(ObjectProvider<JdbcClient> jdbcClientProvider, ObjectMapper objectMapper) {
        this.jdbcClientProvider = jdbcClientProvider;
        this.objectMapper = objectMapper;
    }

    public void save(SecurityEvent event) {
        JdbcClient jdbcClient = jdbcClientProvider.getIfAvailable();
        if (jdbcClient == null) {
            log.debug("No DataSource/JdbcClient available; skipping audit persistence for {}", event.eventType());
            return;
        }

        try {
            String detailsJson = (event.details() == null || event.details().isEmpty())
                    ? "{}"
                    : objectMapper.writeValueAsString(event.details());

            UUID actorUuid = null;
            if (event.actorUserId() != null) {
                try {
                    actorUuid = UUID.fromString(event.actorUserId());
                } catch (IllegalArgumentException ignored) {
                    // Retain null if not a parseable UUID
                }
            }

            jdbcClient.sql("""
                    INSERT INTO security_event (
                        occurred_at, event_type, actor_user_id, subject_type, subject_id,
                        request_id, ip_hash, details
                    ) VALUES (
                        :occurredAt, :eventType, :actorUserId, :subjectType, :subjectId,
                        :requestId, :ipHash, :details::jsonb
                    )
                    """)
                    .param("occurredAt", Timestamp.from(event.occurredAt()))
                    .param("eventType", event.eventType())
                    .param("actorUserId", actorUuid)
                    .param("subjectType", event.subjectType())
                    .param("subjectId", event.subjectId())
                    .param("requestId", event.requestId())
                    .param("ipHash", event.ipHash())
                    .param("details", detailsJson)
                    .update();
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize security event details for eventType={}", event.eventType(), e);
        } catch (Exception e) {
            // AF-03: Evento fallido en persistencia registra error en log técnico sin interrumpir el flujo del emisor
            log.error("Technical error persisting security event: type={}, requestId={}", event.eventType(), event.requestId(), e);
        }
    }
}
