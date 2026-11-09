package com.burnbox.platform;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityEventPublisherTest {

    private final Instant fixedTime = Instant.parse("2026-11-09T10:00:00Z");
    private final Clock clock = Clock.fixed(fixedTime, ZoneOffset.UTC);

    @Test
    @DisplayName("AC-003 / BR-001: Evento emitido captura tiempo del Clock y contexto de request")
    void publishEnrichesEventWithClockAndContext() {
        AtomicReference<SecurityEvent> published = new AtomicReference<>();
        ApplicationEventPublisher eventPublisher = event -> published.set((SecurityEvent) event);
        DefaultSecurityEventPublisher publisher = new DefaultSecurityEventPublisher(eventPublisher, clock);

        RequestContext context = new RequestContext("req-test-123", "actor-user-456", "ip-hash-789");

        RequestContext.runWith(context, () -> {
            publisher.publish("SECRET_VIEWED", "secret", "secret-uuid-1", Map.of("view_count", 1));
        });

        SecurityEvent event = published.get();
        assertThat(event).isNotNull();
        assertThat(event.eventType()).isEqualTo("SECRET_VIEWED");
        assertThat(event.occurredAt()).isEqualTo(fixedTime);
        assertThat(event.requestId()).isEqualTo("req-test-123");
        assertThat(event.actorUserId()).isEqualTo("actor-user-456");
        assertThat(event.ipHash()).isEqualTo("ip-hash-789");
        assertThat(event.subjectType()).isEqualTo("secret");
        assertThat(event.subjectId()).isEqualTo("secret-uuid-1");
        assertThat(event.details()).containsEntry("view_count", 1);
    }

    @Test
    @DisplayName("BR-006 / AC-004: Rechaza cualquier intento de publicar secretos o PII en details")
    void rejectsSensitiveFieldsInDetails() {
        ApplicationEventPublisher eventPublisher = event -> {};
        DefaultSecurityEventPublisher publisher = new DefaultSecurityEventPublisher(eventPublisher, clock);

        assertThatThrownBy(() -> publisher.publish("SECRET_CREATED", Map.of("raw_token", "abc123secret")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("token");

        assertThatThrownBy(() -> publisher.publish("LOGIN_FAILED", Map.of("user_password", "pass123")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("password");

        assertThatThrownBy(() -> publisher.publish("SECRET_FAILED", Map.of("passphrase", "passphrase123")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("passphrase");

        assertThatThrownBy(() -> publisher.publish("USER_REGISTERED", Map.of("user_email", "test@burnbox.io")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("email");
    }
}
