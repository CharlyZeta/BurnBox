package com.burnbox.passkey;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class PasskeyRepository {

    private final ObjectProvider<JdbcClient> jdbcClientProvider;

    public PasskeyRepository(ObjectProvider<JdbcClient> jdbcClientProvider) {
        this.jdbcClientProvider = jdbcClientProvider;
    }

    private JdbcClient jdbc() {
        JdbcClient client = jdbcClientProvider.getIfAvailable();
        if (client == null) {
            throw new IllegalStateException("JdbcClient is not available");
        }
        return client;
    }

    public void insertPasskey(PasskeyCredential cred) {
        jdbc().sql("""
                INSERT INTO passkey_credential (
                    id, user_id, credential_id, public_key, sign_count, transports, label, state, activates_at, created_at, last_used_at
                ) VALUES (
                    :id, :userId, :credentialId, :publicKey, :signCount, :transports, :label, :state, :activatesAt, :createdAt, :lastUsedAt
                )
                """)
                .param("id", cred.id())
                .param("userId", cred.userId())
                .param("credentialId", cred.credentialId())
                .param("publicKey", cred.publicKey())
                .param("signCount", cred.signCount())
                .param("transports", cred.transports())
                .param("label", cred.label())
                .param("state", cred.state().name())
                .param("activatesAt", cred.activatesAt() != null ? OffsetDateTime.ofInstant(cred.activatesAt(), ZoneOffset.UTC) : null)
                .param("createdAt", OffsetDateTime.ofInstant(cred.createdAt(), ZoneOffset.UTC))
                .param("lastUsedAt", cred.lastUsedAt() != null ? OffsetDateTime.ofInstant(cred.lastUsedAt(), ZoneOffset.UTC) : null)
                .update();
    }

    public Optional<PasskeyCredential> findByCredentialId(byte[] credentialId) {
        return jdbc().sql("""
                SELECT id, user_id, credential_id, public_key, sign_count, transports, label, state, activates_at, created_at, last_used_at
                FROM passkey_credential
                WHERE credential_id = :credentialId
                """)
                .param("credentialId", credentialId)
                .query((rs, rowNum) -> new PasskeyCredential(
                        (UUID) rs.getObject("id"),
                        (UUID) rs.getObject("user_id"),
                        rs.getBytes("credential_id"),
                        rs.getBytes("public_key"),
                        rs.getLong("sign_count"),
                        rs.getString("transports"),
                        rs.getString("label"),
                        PasskeyState.valueOf(rs.getString("state")),
                        toInstant(rs.getTimestamp("activates_at")),
                        toInstant(rs.getTimestamp("created_at")),
                        toInstant(rs.getTimestamp("last_used_at"))
                ))
                .optional();
    }

    public List<PasskeyCredential> findByUserId(UUID userId) {
        return jdbc().sql("""
                SELECT id, user_id, credential_id, public_key, sign_count, transports, label, state, activates_at, created_at, last_used_at
                FROM passkey_credential
                WHERE user_id = :userId
                ORDER BY created_at ASC
                """)
                .param("userId", userId)
                .query((rs, rowNum) -> new PasskeyCredential(
                        (UUID) rs.getObject("id"),
                        (UUID) rs.getObject("user_id"),
                        rs.getBytes("credential_id"),
                        rs.getBytes("public_key"),
                        rs.getLong("sign_count"),
                        rs.getString("transports"),
                        rs.getString("label"),
                        PasskeyState.valueOf(rs.getString("state")),
                        toInstant(rs.getTimestamp("activates_at")),
                        toInstant(rs.getTimestamp("created_at")),
                        toInstant(rs.getTimestamp("last_used_at"))
                ))
                .list();
    }

    public int countActiveByUserId(UUID userId) {
        return jdbc().sql("""
                SELECT COUNT(*)
                FROM passkey_credential
                WHERE user_id = :userId AND state = 'ACTIVE'
                """)
                .param("userId", userId)
                .query(Integer.class)
                .single();
    }

    public void updateSignCountAndLastUsed(byte[] credentialId, long newSignCount, Instant lastUsedAt) {
        jdbc().sql("""
                UPDATE passkey_credential
                SET sign_count = :signCount, last_used_at = :lastUsedAt
                WHERE credential_id = :credentialId
                """)
                .param("signCount", newSignCount)
                .param("lastUsedAt", OffsetDateTime.ofInstant(lastUsedAt, ZoneOffset.UTC))
                .param("credentialId", credentialId)
                .update();
    }

    public void updateState(byte[] credentialId, PasskeyState newState) {
        jdbc().sql("""
                UPDATE passkey_credential
                SET state = :state
                WHERE credential_id = :credentialId
                """)
                .param("state", newState.name())
                .param("credentialId", credentialId)
                .update();
    }

    private static Instant toInstant(Timestamp ts) {
        return ts != null ? ts.toInstant() : null;
    }
}
