package com.burnbox.audit;

import com.burnbox.platform.SecurityEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for storing security audit events using explicit SQL with JdbcClient.
 * Enforces cryptographic hash chain (BR-001, BR-002, BR-004),
 * AF-02 (empty JSON details if null/empty), and AF-03 (safe failure logging).
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

    public synchronized void save(SecurityEvent event) {
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

            // Consultar el hash del último evento registrado en la cadena (BR-001)
            Optional<String> lastHashOpt = jdbcClient.sql("""
                    SELECT hash FROM security_event
                    ORDER BY id DESC
                    LIMIT 1
                    """)
                    .query(String.class)
                    .optional();

            String prevHash = lastHashOpt.orElse(AuditHashCalculator.GENESIS_PREV_HASH);
            long epochMilli = event.occurredAt().toEpochMilli();

            String calculatedHash = AuditHashCalculator.calculateHash(
                    prevHash,
                    epochMilli,
                    event.eventType(),
                    actorUuid,
                    event.subjectType(),
                    event.subjectId(),
                    event.requestId(),
                    event.ipHash(),
                    detailsJson
            );

            jdbcClient.sql("""
                    INSERT INTO security_event (
                        occurred_at, event_type, actor_user_id, subject_type, subject_id,
                        request_id, ip_hash, details, prev_hash, hash
                    ) VALUES (
                        :occurredAt, :eventType, :actorUserId, :subjectType, :subjectId,
                        :requestId, :ipHash, :details::jsonb, :prevHash, :hash
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
                    .param("prevHash", prevHash)
                    .param("hash", calculatedHash)
                    .update();
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize security event details for eventType={}", event.eventType(), e);
        } catch (Exception e) {
            // AF-03: Evento fallido en persistencia registra error en log técnico sin interrumpir el flujo del emisor
            log.error("Technical error persisting security event: type={}, requestId={}", event.eventType(), event.requestId(), e);
        }
    }

    public List<SecurityEventRecord> findByActorUserId(UUID actorUserId, int limit) {
        JdbcClient jdbcClient = jdbcClientProvider.getIfAvailable();
        if (jdbcClient == null || actorUserId == null) {
            return Collections.emptyList();
        }

        return jdbcClient.sql("""
                SELECT id, occurred_at, event_type, actor_user_id, subject_type, subject_id,
                       request_id, ip_hash, details::text as details, prev_hash, hash
                FROM security_event
                WHERE actor_user_id = :actorUserId
                ORDER BY occurred_at DESC, id DESC
                LIMIT :limit
                """)
                .param("actorUserId", actorUserId)
                .param("limit", limit)
                .query(new SecurityEventRowMapper())
                .list();
    }

    public List<SecurityEventRecord> findAllOrderedById() {
        JdbcClient jdbcClient = jdbcClientProvider.getIfAvailable();
        if (jdbcClient == null) {
            return Collections.emptyList();
        }

        return jdbcClient.sql("""
                SELECT id, occurred_at, event_type, actor_user_id, subject_type, subject_id,
                       request_id, ip_hash, details::text as details, prev_hash, hash
                FROM security_event
                ORDER BY id ASC
                """)
                .query(new SecurityEventRowMapper())
                .list();
    }

    private static class SecurityEventRowMapper implements RowMapper<SecurityEventRecord> {
        @Override
        public SecurityEventRecord mapRow(ResultSet rs, int rowNum) throws SQLException {
            Long id = rs.getLong("id");
            Timestamp occurredTs = rs.getTimestamp("occurred_at");
            String eventType = rs.getString("event_type");
            UUID actorUserId = rs.getObject("actor_user_id", UUID.class);
            String subjectType = rs.getString("subject_type");
            String subjectId = rs.getString("subject_id");
            String requestId = rs.getString("request_id");
            String ipHash = rs.getString("ip_hash");
            String details = rs.getString("details");
            String prevHash = rs.getString("prev_hash");
            String hash = rs.getString("hash");

            return new SecurityEventRecord(
                    id,
                    occurredTs.toInstant(),
                    eventType,
                    actorUserId,
                    subjectType,
                    subjectId,
                    requestId,
                    ipHash,
                    details,
                    prevHash,
                    hash
            );
        }
    }
}
