package com.burnbox.audit;

import com.burnbox.platform.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuditChainIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SecurityEventRepository repository;

    @MockitoBean
    private AuditChainVerifier verifier;

    @Test
    @DisplayName("AC-008 & AF-04: Visitante anónimo que accede a /account/events es redirigido a /login")
    void anonymousAccessRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/account/events"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    @DisplayName("AC-007 & BR-006: Usuario autenticado visualiza sus eventos de seguridad personales")
    @WithMockUser(username = "11111111-1111-1111-1111-111111111111")
    void authenticatedUserViewsTheirSecurityEvents() throws Exception {
        UUID userId = UUID.fromString("11111111-1111-1111-1111-111111111111");

        SecurityEventRecord record = new SecurityEventRecord(
                1L,
                Instant.parse("2026-11-09T18:00:00Z"),
                "USER_LOGGED_IN",
                userId,
                "session",
                "sess-1",
                "req-1",
                "ip-hash-1",
                "{\"method\":\"google\"}",
                AuditHashCalculator.GENESIS_PREV_HASH,
                "a".repeat(64)
        );

        when(repository.findByActorUserId(eq(userId), anyInt())).thenReturn(List.of(record));
        when(verifier.verifyChain()).thenReturn(new AuditVerificationResult.Valid(1, "a".repeat(64)));

        mockMvc.perform(get("/account/events"))
                .andExpect(status().isOk())
                .andExpect(view().name("account-events"))
                .andExpect(model().attributeExists("events"))
                .andExpect(model().attributeExists("integrity"))
                .andExpect(header().string("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"));
    }
}
