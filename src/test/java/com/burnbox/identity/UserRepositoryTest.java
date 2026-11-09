package com.burnbox.identity;

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

class UserRepositoryTest {

    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    private ObjectProvider<JdbcClient> providerOf(JdbcClient client) {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcClient> provider = Mockito.mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    @Test
    @DisplayName("AC-008: UserRepository opera sobre app_user y linked_identity cuando hay JdbcClient")
    void repositoryInteractsWithJdbcClient() {
        JdbcClient jdbcClient = Mockito.mock(JdbcClient.class);
        JdbcClient.StatementSpec spec = Mockito.mock(JdbcClient.StatementSpec.class);

        when(jdbcClient.sql(anyString())).thenReturn(spec);
        when(spec.param(anyString(), any())).thenReturn(spec);
        when(spec.update()).thenReturn(1);

        UserRepository repository = new UserRepository(providerOf(jdbcClient));

        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser(
                userId, "Test User", "test@burnbox.io", true,
                UserStatus.ACTIVE, null, "es", fixedTime, fixedTime
        );

        repository.insertUser(user);
        verify(jdbcClient).sql(contains("INSERT INTO app_user"));

        LinkedIdentity identity = new LinkedIdentity(
                UUID.randomUUID(), userId, IdentityProvider.GOOGLE, "https://accounts.google.com",
                "sub-999", "test@burnbox.io", true, fixedTime, fixedTime
        );

        repository.insertIdentity(identity);
        verify(jdbcClient).sql(contains("INSERT INTO linked_identity"));
    }

    @Test
    @DisplayName("AC-008: Si no hay base de datos configurada, el repositorio lanza IllegalStateException explicito")
    void repositoryThrowsWhenNoDatabase() {
        UserRepository repository = new UserRepository(providerOf(null));

        assertThatThrownBy(() -> repository.findById(UUID.randomUUID()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JdbcClient is not available");

        assertThatThrownBy(() -> repository.findIdentity("https://accounts.google.com", "sub"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JdbcClient is not available");
    }
}
