package com.burnbox.secret;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for Secret domain entity using explicit SQL with JdbcClient.
 * Employs pessimistic locking (FOR UPDATE) for atomic state transitions (BR-004).
 */
@Repository
public class SecretRepository {

    private final ObjectProvider<JdbcClient> jdbcClientProvider;

    public SecretRepository(ObjectProvider<JdbcClient> jdbcClientProvider) {
        this.jdbcClientProvider = jdbcClientProvider;
    }

    private JdbcClient client() {
        JdbcClient client = jdbcClientProvider.getIfAvailable();
        if (client == null) {
            throw new IllegalStateException("JdbcClient is not available");
        }
        return client;
    }

    public void insert(Secret secret) {
        client().sql("""
                INSERT INTO secret (
                    id, owner_user_id, token_hash, ciphertext, nonce, wrapped_dek,
                    key_version, format_version, passphrase_salt, passphrase_protected,
                    max_views, views, state, expires_at, created_at, consumed_at,
                    failed_attempts, recipient_email, label
                ) VALUES (
                    :id, :ownerUserId, :tokenHash, :ciphertext, :nonce, :wrappedDek,
                    :keyVersion, :formatVersion, :passphraseSalt, :passphraseProtected,
                    :maxViews, :views, :state, :expiresAt, :createdAt, :consumedAt,
                    :failedAttempts, :recipientEmail, :label
                )
                """)
                .param("id", secret.id())
                .param("ownerUserId", secret.ownerUserId())
                .param("tokenHash", secret.tokenHash())
                .param("ciphertext", secret.ciphertext())
                .param("nonce", secret.nonce())
                .param("wrappedDek", secret.wrappedDek())
                .param("keyVersion", secret.keyVersion())
                .param("formatVersion", secret.formatVersion())
                .param("passphraseSalt", secret.passphraseSalt())
                .param("passphraseProtected", secret.passphraseProtected())
                .param("maxViews", secret.maxViews())
                .param("views", secret.views())
                .param("state", secret.state().name())
                .param("expiresAt", Timestamp.from(secret.expiresAt()))
                .param("createdAt", Timestamp.from(secret.createdAt()))
                .param("consumedAt", secret.consumedAt() != null ? Timestamp.from(secret.consumedAt()) : null)
                .param("failedAttempts", secret.failedAttempts())
                .param("recipientEmail", secret.recipientEmail())
                .param("label", secret.label())
                .update();
    }

    public Optional<Secret> findByTokenHashForUpdate(String tokenHash) {
        return client().sql("""
                SELECT * FROM secret
                WHERE token_hash = :tokenHash
                FOR UPDATE
                """)
                .param("tokenHash", tokenHash)
                .query(new SecretRowMapper())
                .optional();
    }

    public Optional<Secret> findById(UUID id) {
        return client().sql("""
                SELECT * FROM secret
                WHERE id = :id
                """)
                .param("id", id)
                .query(new SecretRowMapper())
                .optional();
    }

    public void recordFailedAttempt(UUID id, int failedAttempts) {
        client().sql("""
                UPDATE secret
                SET failed_attempts = :failedAttempts
                WHERE id = :id
                """)
                .param("failedAttempts", failedAttempts)
                .param("id", id)
                .update();
    }

    public void destroyByAbuse(UUID id, int failedAttempts, Instant destroyedAt) {
        client().sql("""
                UPDATE secret
                SET state = 'DESTROYED_BY_ABUSE',
                    failed_attempts = :failedAttempts,
                    consumed_at = :destroyedAt,
                    ciphertext = NULL,
                    nonce = NULL,
                    wrapped_dek = NULL,
                    passphrase_salt = NULL,
                    recipient_email = NULL
                WHERE id = :id
                """)
                .param("failedAttempts", failedAttempts)
                .param("destroyedAt", Timestamp.from(destroyedAt))
                .param("id", id)
                .update();
    }

    public void updateStateAndViews(UUID id, SecretState newState, int views, Instant consumedAt) {
        if (newState.isTerminal()) {
            // BR-003: Vaciado irrevocable de columnas sensibles en estados terminales
            client().sql("""
                    UPDATE secret
                    SET state = :state,
                        views = :views,
                        consumed_at = :consumedAt,
                        ciphertext = NULL,
                        nonce = NULL,
                        wrapped_dek = NULL,
                        passphrase_salt = NULL,
                        recipient_email = NULL
                    WHERE id = :id
                    """)
                    .param("state", newState.name())
                    .param("views", views)
                    .param("consumedAt", consumedAt != null ? Timestamp.from(consumedAt) : null)
                    .param("id", id)
                    .update();
        } else {
            client().sql("""
                    UPDATE secret
                    SET state = :state,
                        views = :views,
                        consumed_at = :consumedAt
                    WHERE id = :id
                    """)
                    .param("state", newState.name())
                    .param("views", views)
                    .param("consumedAt", consumedAt != null ? Timestamp.from(consumedAt) : null)
                    .param("id", id)
                    .update();
        }
    }

    private static class SecretRowMapper implements RowMapper<Secret> {
        @Override
        public Secret mapRow(ResultSet rs, int rowNum) throws SQLException {
            UUID id = rs.getObject("id", UUID.class);
            UUID ownerUserId = rs.getObject("owner_user_id", UUID.class);
            String tokenHash = rs.getString("token_hash");
            byte[] ciphertext = rs.getBytes("ciphertext");
            byte[] nonce = rs.getBytes("nonce");
            byte[] wrappedDek = rs.getBytes("wrapped_dek");
            int keyVersion = rs.getInt("key_version");
            int formatVersion = rs.getInt("format_version");
            byte[] passphraseSalt = rs.getBytes("passphrase_salt");
            boolean passphraseProtected = rs.getBoolean("passphrase_protected");
            int maxViews = rs.getInt("max_views");
            int views = rs.getInt("views");
            SecretState state = SecretState.valueOf(rs.getString("state"));
            Timestamp expiresTs = rs.getTimestamp("expires_at");
            Timestamp createdTs = rs.getTimestamp("created_at");
            Timestamp consumedTs = rs.getTimestamp("consumed_at");
            int failedAttempts = rs.getInt("failed_attempts");
            String recipientEmail = rs.getString("recipient_email");
            String label = rs.getString("label");

            return new Secret(
                    id,
                    ownerUserId,
                    tokenHash,
                    ciphertext,
                    nonce,
                    wrappedDek,
                    keyVersion,
                    formatVersion,
                    passphraseSalt,
                    passphraseProtected,
                    maxViews,
                    views,
                    state,
                    expiresTs.toInstant(),
                    createdTs.toInstant(),
                    consumedTs != null ? consumedTs.toInstant() : null,
                    failedAttempts,
                    recipientEmail,
                    label
            );
        }
    }
}
