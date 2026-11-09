package com.burnbox.secret;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
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

    public record ExpiredSecretRecord(UUID id, String tokenHash) {}

    public List<ExpiredSecretRecord> purgeExpiredSecrets(Instant now, int batchSize) {
        return client().sql("""
                WITH to_expire AS (
                    SELECT id, token_hash FROM secret
                    WHERE state = 'ACTIVE' AND expires_at < :now
                    ORDER BY expires_at ASC
                    LIMIT :batchSize
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE secret s
                SET state = 'EXPIRED',
                    consumed_at = :now,
                    ciphertext = NULL,
                    nonce = NULL,
                    wrapped_dek = NULL,
                    passphrase_salt = NULL,
                    recipient_email = NULL
                FROM to_expire
                WHERE s.id = to_expire.id
                RETURNING s.id, s.token_hash
                """)
                .param("now", Timestamp.from(now))
                .param("batchSize", batchSize)
                .query((rs, rowNum) -> new ExpiredSecretRecord(
                        rs.getObject("id", UUID.class),
                        rs.getString("token_hash")
                ))
                .list();
    }

    public int deleteTombstones(Instant olderThan, int batchSize) {
        return client().sql("""
                WITH to_delete AS (
                    SELECT id FROM secret
                    WHERE state <> 'ACTIVE'
                      AND ((consumed_at IS NOT NULL AND consumed_at < :olderThan) OR (consumed_at IS NULL AND expires_at < :olderThan))
                    ORDER BY id ASC
                    LIMIT :batchSize
                    FOR UPDATE SKIP LOCKED
                )
                DELETE FROM secret s
                USING to_delete
                WHERE s.id = to_delete.id
                """)
                .param("olderThan", Timestamp.from(olderThan))
                .param("batchSize", batchSize)
                .update();
    }

    public record PendingReEnvelopeRecord(UUID id, byte[] wrappedDek, int keyVersion) {}

    public List<PendingReEnvelopeRecord> findSecretsPendingReEnvelope(int targetKeyVersion, int batchSize) {
        return client().sql("""
                SELECT id, wrapped_dek, key_version
                FROM secret
                WHERE key_version < :targetKeyVersion
                  AND state = 'ACTIVE'
                  AND wrapped_dek IS NOT NULL
                ORDER BY id ASC
                LIMIT :batchSize
                FOR UPDATE SKIP LOCKED
                """)
                .param("targetKeyVersion", targetKeyVersion)
                .param("batchSize", batchSize)
                .query((rs, rowNum) -> new PendingReEnvelopeRecord(
                        rs.getObject("id", UUID.class),
                        rs.getBytes("wrapped_dek"),
                        rs.getInt("key_version")
                ))
                .list();
    }

    public int updateReEnvelopedSecret(UUID id, byte[] newWrappedDek, int newKeyVersion) {
        return client().sql("""
                UPDATE secret
                SET wrapped_dek = :newWrappedDek,
                    key_version = :newKeyVersion
                WHERE id = :id
                """)
                .param("newWrappedDek", newWrappedDek)
                .param("newKeyVersion", newKeyVersion)
                .param("id", id)
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

    public Optional<Secret> findByTokenHash(String tokenHash) {
        return client().sql("""
                SELECT * FROM secret
                WHERE token_hash = :tokenHash
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
