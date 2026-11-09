package com.burnbox.audit;

import com.burnbox.platform.RequestContext;
import com.burnbox.platform.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Map;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;

@SpringBootTest(properties = "management.server.port=")
@ActiveProfiles("test")
class AuditModuleIntegrationTest {

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @MockitoBean
    private SecurityEventRepository repository;

    @Test
    @DisplayName("AC-008 / BR-001: Módulo audit consume evento de dominio emitido por la aplicación")
    void auditModuleConsumesSecurityEvent() {
        SecurityEvent event = new SecurityEvent(
                "SECRET_CONSUMED",
                Instant.parse("2026-11-09T10:00:00Z"),
                "actor-999",
                "req-audit-test",
                "ip-hash-abc",
                "secret",
                "sec-id-123",
                Map.of("action", "burn")
        );

        eventPublisher.publishEvent(event);

        verify(repository).save(argThat(saved ->
                "SECRET_CONSUMED".equals(saved.eventType()) &&
                "req-audit-test".equals(saved.requestId()) &&
                "sec-id-123".equals(saved.subjectId())
        ));
    }
}
