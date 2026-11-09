package com.burnbox.passkey;

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

class PasskeyRepositoryTest {

    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    private ObjectProvider<JdbcClient> providerOf(JdbcClient client) {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcClient> provider = Mockito.mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    @Test
    @DisplayName("AC-008: PasskeyRepository opera sobre passkey_credential cuando hay JdbcClient")
    void repositoryInteractsWithJdbcClient() {
        JdbcClient jdbcClient = Mockito.mock(JdbcClient.class);
        JdbcClient.StatementSpec spec = Mockito.mock(JdbcClient.StatementSpec.class);

        when(jdbcClient.sql(anyString())).thenReturn(spec);
        when(spec.param(anyString(), any())).thenReturn(spec);
        when(spec.update()).thenReturn(1);

        PasskeyRepository repository = new PasskeyRepository(providerOf(jdbcClient));

        UUID userId = UUID.randomUUID();
        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, new byte[]{1, 2, 3}, new byte[]{4, 5, 6},
                0, "internal", "TouchID", PasskeyState.ACTIVE, null, fixedTime, null
        );

        repository.insertPasskey(cred);
        verify(jdbcClient).sql(contains("INSERT INTO passkey_credential"));

        repository.updateSignCountAndLastUsed(cred.credentialId(), 15, fixedTime);
        verify(jdbcClient).sql(contains("UPDATE passkey_credential"));

        repository.updateState(cred.credentialId(), PasskeyState.REVOKED);
        verify(jdbcClient, times(2)).sql(contains("UPDATE passkey_credential"));
    }

    @Test
    @DisplayName("AC-008: Lanza IllegalStateException cuando JdbcClient no está disponible")
    void repositoryThrowsWhenNoDatabase() {
        PasskeyRepository repository = new PasskeyRepository(providerOf(null));

        assertThatThrownBy(() -> repository.findByCredentialId(new byte[]{1}))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JdbcClient is not available");
    }
}
