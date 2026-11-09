package com.burnbox.session;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class UserSessionRepository {

    private final ObjectProvider<JdbcClient> jdbcClientProvider;

    public UserSessionRepository(ObjectProvider<JdbcClient> jdbcClientProvider) {
        this.jdbcClientProvider = jdbcClientProvider;
    }

    private JdbcClient jdbc() {
        JdbcClient client = jdbcClientProvider.getIfAvailable();
        if (client == null) {
            throw new IllegalStateException("JdbcClient is not available");
        }
        return client;
    }

    public void insertSession(UserSessionMeta session) {
        jdbc().sql("""
                INSERT INTO user_session_meta (
                    id, session_id, user_id, ip_hash, user_agent_summary, created_at, last_accessed_at, revoked
                ) VALUES (
                    :id, :sessionId, :userId, :ipHash, :userAgentSummary, :createdAt, :lastAccessedAt, :revoked
                )
                """)
                .param("id", session.id())
                .param("sessionId", session.sessionId())
                .param("userId", session.userId())
                .param("ipHash", session.ipHash())
                .param("userAgentSummary", session.userAgentSummary())
                .param("createdAt", OffsetDateTime.ofInstant(session.createdAt(), ZoneOffset.UTC))
                .param("lastAccessedAt", OffsetDateTime.ofInstant(session.lastAccessedAt(), ZoneOffset.UTC))
                .param("revoked", session.revoked())
                .update();
    }

    public Optional<UserSessionMeta> findBySessionId(String sessionId) {
        return jdbc().sql("""
                SELECT id, session_id, user_id, ip_hash, user_agent_summary, created_at, last_accessed_at, revoked
                FROM user_session_meta
                WHERE session_id = :sessionId
                """)
                .param("sessionId", sessionId)
                .query((rs, rowNum) -> new UserSessionMeta(
                        (UUID) rs.getObject("id"),
                        rs.getString("session_id"),
                        (UUID) rs.getObject("user_id"),
                        rs.getString("ip_hash"),
                        rs.getString("user_agent_summary"),
                        toInstant(rs.getTimestamp("created_at")),
                        toInstant(rs.getTimestamp("last_accessed_at")),
                        rs.getBoolean("revoked")
                ))
                .optional();
    }

    public List<UserSessionMeta> findActiveByUserId(UUID userId) {
        return jdbc().sql("""
                SELECT id, session_id, user_id, ip_hash, user_agent_summary, created_at, last_accessed_at, revoked
                FROM user_session_meta
                WHERE user_id = :userId AND revoked = FALSE
                ORDER BY last_accessed_at DESC
                """)
                .param("userId", userId)
                .query((rs, rowNum) -> new UserSessionMeta(
                        (UUID) rs.getObject("id"),
                        rs.getString("session_id"),
                        (UUID) rs.getObject("user_id"),
                        rs.getString("ip_hash"),
                        rs.getString("user_agent_summary"),
                        toInstant(rs.getTimestamp("created_at")),
                        toInstant(rs.getTimestamp("last_accessed_at")),
                        rs.getBoolean("revoked")
                ))
                .list();
    }

    public void updateLastAccessed(String sessionId, Instant lastAccessedAt) {
        jdbc().sql("""
                UPDATE user_session_meta
                SET last_accessed_at = :lastAccessedAt
                WHERE session_id = :sessionId
                """)
                .param("sessionId", sessionId)
                .param("lastAccessedAt", OffsetDateTime.ofInstant(lastAccessedAt, ZoneOffset.UTC))
                .update();
    }

    public void markRevoked(String sessionId) {
        jdbc().sql("""
                UPDATE user_session_meta
                SET revoked = TRUE
                WHERE session_id = :sessionId
                """)
                .param("sessionId", sessionId)
                .update();
    }

    public void revokeOthersForUser(UUID userId, String currentSessionId) {
        jdbc().sql("""
                UPDATE user_session_meta
                SET revoked = TRUE
                WHERE user_id = :userId AND session_id != :currentSessionId AND revoked = FALSE
                """)
                .param("userId", userId)
                .param("currentSessionId", currentSessionId)
                .update();
    }

    private static Instant toInstant(Timestamp ts) {
        return ts != null ? ts.toInstant() : null;
    }
}
