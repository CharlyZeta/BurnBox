package com.burnbox.identity;

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

@Repository
public class UserRepository {

    private final ObjectProvider<JdbcClient> jdbcClientProvider;

    public UserRepository(ObjectProvider<JdbcClient> jdbcClientProvider) {
        this.jdbcClientProvider = jdbcClientProvider;
    }

    private JdbcClient client() {
        JdbcClient client = jdbcClientProvider.getIfAvailable();
        if (client == null) {
            throw new IllegalStateException("JdbcClient is not available");
        }
        return client;
    }

    public void insertUser(AppUser user) {
        client().sql("""
                INSERT INTO app_user (
                    id, display_name, primary_email, primary_email_verified,
                    status, deletion_scheduled_at, locale, created_at, last_login_at
                ) VALUES (
                    :id, :displayName, :primaryEmail, :primaryEmailVerified,
                    :status, :deletionScheduledAt, :locale, :createdAt, :lastLoginAt
                )
                """)
                .param("id", user.id())
                .param("displayName", user.displayName())
                .param("primaryEmail", user.primaryEmail())
                .param("primaryEmailVerified", user.primaryEmailVerified())
                .param("status", user.status().name())
                .param("deletionScheduledAt", user.deletionScheduledAt() != null ? Timestamp.from(user.deletionScheduledAt()) : null)
                .param("locale", user.locale())
                .param("createdAt", Timestamp.from(user.createdAt()))
                .param("lastLoginAt", user.lastLoginAt() != null ? Timestamp.from(user.lastLoginAt()) : null)
                .update();
    }

    public Optional<AppUser> findById(UUID id) {
        return client().sql("SELECT * FROM app_user WHERE id = :id")
                .param("id", id)
                .query(new AppUserRowMapper())
                .optional();
    }

    public Optional<AppUser> findByVerifiedEmail(String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        return client().sql("SELECT * FROM app_user WHERE primary_email = :email AND primary_email_verified = TRUE")
                .param("email", email.trim().toLowerCase())
                .query(new AppUserRowMapper())
                .optional();
    }

    public void updateLastLogin(UUID userId, Instant loginTime) {
        client().sql("UPDATE app_user SET last_login_at = :lastLoginAt WHERE id = :id")
                .param("lastLoginAt", Timestamp.from(loginTime))
                .param("id", userId)
                .update();
    }

    public void insertIdentity(LinkedIdentity identity) {
        client().sql("""
                INSERT INTO linked_identity (
                    id, user_id, provider, issuer, subject,
                    email_at_link, email_verified_at_link, created_at, last_used_at
                ) VALUES (
                    :id, :userId, :provider, :issuer, :subject,
                    :emailAtLink, :emailVerifiedAtLink, :createdAt, :lastUsedAt
                )
                """)
                .param("id", identity.id())
                .param("userId", identity.userId())
                .param("provider", identity.provider().name())
                .param("issuer", identity.issuer())
                .param("subject", identity.subject())
                .param("emailAtLink", identity.emailAtLink())
                .param("emailVerifiedAtLink", identity.emailVerifiedAtLink())
                .param("createdAt", Timestamp.from(identity.createdAt()))
                .param("lastUsedAt", identity.lastUsedAt() != null ? Timestamp.from(identity.lastUsedAt()) : null)
                .update();
    }

    public Optional<LinkedIdentity> findIdentity(String issuer, String subject) {
        return client().sql("SELECT * FROM linked_identity WHERE issuer = :issuer AND subject = :subject")
                .param("issuer", issuer)
                .param("subject", subject)
                .query(new LinkedIdentityRowMapper())
                .optional();
    }

    public void updateIdentityLastUsed(UUID identityId, Instant lastUsed) {
        client().sql("UPDATE linked_identity SET last_used_at = :lastUsedAt WHERE id = :id")
                .param("lastUsedAt", Timestamp.from(lastUsed))
                .param("id", identityId)
                .update();
    }

    private static class AppUserRowMapper implements RowMapper<AppUser> {
        @Override
        public AppUser mapRow(ResultSet rs, int rowNum) throws SQLException {
            UUID id = rs.getObject("id", UUID.class);
            String displayName = rs.getString("display_name");
            String primaryEmail = rs.getString("primary_email");
            boolean emailVerified = rs.getBoolean("primary_email_verified");
            UserStatus status = UserStatus.valueOf(rs.getString("status"));
            Timestamp delTs = rs.getTimestamp("deletion_scheduled_at");
            String locale = rs.getString("locale");
            Timestamp createdTs = rs.getTimestamp("created_at");
            Timestamp lastLoginTs = rs.getTimestamp("last_login_at");

            return new AppUser(
                    id,
                    displayName,
                    primaryEmail,
                    emailVerified,
                    status,
                    delTs != null ? delTs.toInstant() : null,
                    locale,
                    createdTs.toInstant(),
                    lastLoginTs != null ? lastLoginTs.toInstant() : null
            );
        }
    }

    private static class LinkedIdentityRowMapper implements RowMapper<LinkedIdentity> {
        @Override
        public LinkedIdentity mapRow(ResultSet rs, int rowNum) throws SQLException {
            UUID id = rs.getObject("id", UUID.class);
            UUID userId = rs.getObject("user_id", UUID.class);
            IdentityProvider provider = IdentityProvider.valueOf(rs.getString("provider"));
            String issuer = rs.getString("issuer");
            String subject = rs.getString("subject");
            String email = rs.getString("email_at_link");
            boolean emailVerified = rs.getBoolean("email_verified_at_link");
            Timestamp createdTs = rs.getTimestamp("created_at");
            Timestamp lastUsedTs = rs.getTimestamp("last_used_at");

            return new LinkedIdentity(
                    id,
                    userId,
                    provider,
                    issuer,
                    subject,
                    email,
                    emailVerified,
                    createdTs.toInstant(),
                    lastUsedTs != null ? lastUsedTs.toInstant() : null
            );
        }
    }
}
