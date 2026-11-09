package com.burnbox.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class UserSessionRepositoryTest {

    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    private ObjectProvider<JdbcClient> providerOf(JdbcClient client) {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcClient> provider = Mockito.mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    @Test
    @DisplayName("AC-008: UserSessionRepository opera sobre user_session_meta cuando hay JdbcClient")
    void repositoryInteractsWithJdbcClient() {
        JdbcClient jdbcClient = Mockito.mock(JdbcClient.class);
        JdbcClient.StatementSpec spec = Mockito.mock(JdbcClient.StatementSpec.class);

        when(jdbcClient.sql(anyString())).thenReturn(spec);
        when(spec.param(anyString(), any())).thenReturn(spec);
        when(spec.update()).thenReturn(1);

        UserSessionRepository repository = new UserSessionRepository(providerOf(jdbcClient));

        UUID userId = UUID.randomUUID();
        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(), "sess-repo-test", userId, "ip-hash", "Agent", fixedTime, fixedTime, false
        );

        repository.insertSession(session);
        verify(jdbcClient).sql(contains("INSERT INTO user_session_meta"));

        repository.updateLastAccessed("sess-repo-test", fixedTime);
        verify(jdbcClient).sql(contains("UPDATE user_session_meta"));

        repository.markRevoked("sess-repo-test");
        verify(jdbcClient, times(2)).sql(contains("UPDATE user_session_meta"));

        repository.revokeOthersForUser(userId, "sess-repo-test");
        verify(jdbcClient, times(3)).sql(contains("UPDATE user_session_meta"));
    }

    @Test
    @DisplayName("AC-008: Lanza IllegalStateException cuando JdbcClient no está disponible")
    void repositoryThrowsWhenNoDatabase() {
        UserSessionRepository repository = new UserSessionRepository(providerOf(null));

        assertThatThrownBy(() -> repository.findBySessionId("sess-id"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JdbcClient is not available");
    }
}
