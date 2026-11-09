package com.burnbox.notification;

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

class NotificationRepositoryTest {

    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    private ObjectProvider<JdbcClient> providerOf(JdbcClient client) {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcClient> provider = Mockito.mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(client);
        return provider;
    }

    @Test
    @DisplayName("AC-008: NotificationRepository opera sobre notification_delivery cuando hay JdbcClient")
    void repositoryInteractsWithJdbcClient() {
        JdbcClient jdbcClient = Mockito.mock(JdbcClient.class);
        JdbcClient.StatementSpec spec = Mockito.mock(JdbcClient.StatementSpec.class);

        when(jdbcClient.sql(anyString())).thenReturn(spec);
        when(spec.param(anyString(), any())).thenReturn(spec);
        when(spec.update()).thenReturn(1);

        NotificationRepository repository = new NotificationRepository(providerOf(jdbcClient));

        UUID notificationId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        NotificationDelivery delivery = new NotificationDelivery(
                notificationId, "source-1", userId, "secret-accessed",
                "test@burnbox.io", "EMAIL", NotificationStatus.PENDING, 0, null, null, fixedTime, null
        );

        repository.insertNotification(delivery);
        verify(jdbcClient).sql(contains("INSERT INTO notification_delivery"));

        repository.updateStatusSent(notificationId, fixedTime);
        verify(jdbcClient).sql(contains("UPDATE notification_delivery"));

        repository.updateStatusFailed(notificationId, 1, fixedTime, "Error");
        verify(jdbcClient, times(2)).sql(contains("UPDATE notification_delivery"));

        repository.updateStatusDead(notificationId, 5, "Dead Error");
        verify(jdbcClient, times(3)).sql(contains("UPDATE notification_delivery"));
    }

    @Test
    @DisplayName("AC-008: Lanza IllegalStateException cuando JdbcClient no está disponible")
    void repositoryThrowsWhenNoDatabase() {
        NotificationRepository repository = new NotificationRepository(providerOf(null));

        assertThatThrownBy(() -> repository.findBySourceTemplateAndUser("src", "tpl", UUID.randomUUID()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JdbcClient is not available");
    }
}
