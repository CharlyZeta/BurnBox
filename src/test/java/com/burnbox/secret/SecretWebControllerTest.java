package com.burnbox.secret;

import com.burnbox.platform.SecurityConfig;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = SecretWebController.class)
@Import(SecurityConfig.class)
class SecretWebControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SecretService secretService;

    @Test
    @DisplayName("AC-001: GET / renderiza formulario de creación con CSRF y opciones")
    void indexRendersCreationForm() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(model().attributeExists("form"));
    }

    @Test
    @DisplayName("AC-002: POST /secrets válido responde 200 y renderiza secret-created con enlace")
    void postValidSecretCreatesAndRendersLink() throws Exception {
        UUID secretId = UUID.randomUUID();
        Instant expires = Instant.parse("2026-11-09T12:00:00Z");
        CreateSecretResult result = new CreateSecretResult(secretId, "abc123token456", "hash", expires);

        when(secretService.createSecret(any(CreateSecretCommand.class))).thenReturn(result);

        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "SuperConfidentialInformation123")
                        .param("ttl", "1h")
                        .param("maxViews", "1"))
                .andExpect(status().isOk())
                .andExpect(view().name("secret-created"))
                .andExpect(model().attributeExists("secretUrl"))
                .andExpect(model().attribute("rawToken", "abc123token456"))
                .andExpect(model().attribute("maxViews", 1))
                .andExpect(header().string("Cache-Control", Matchers.containsString("no-store")))
                .andExpect(header().string("X-Robots-Tag", "noindex, nofollow"));

        verify(secretService).createSecret(argThat(cmd ->
                "SuperConfidentialInformation123".equals(new String(cmd.plaintext())) &&
                Duration.ofHours(1).equals(cmd.ttl()) &&
                cmd.maxViews() == 1 &&
                cmd.ownerUserId() == null
        ));
    }

    @Test
    @DisplayName("AC-003 / AF-01: Contenido en blanco rechaza con 400 y no invoca al servicio")
    void blankContentRejectsWith400() throws Exception {
        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "   ")
                        .param("ttl", "1h")
                        .param("maxViews", "1"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("index"))
                .andExpect(model().attributeExists("error"));

        verifyNoInteractions(secretService);
    }

    @Test
    @DisplayName("AC-004 / AF-02 / BR-001: Contenido que excede 64 KiB rechaza con 400")
    void contentExceeding64KiBRejectsWith400() throws Exception {
        String oversized = "A".repeat(65537); // 64 KiB + 1 byte

        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", oversized)
                        .param("ttl", "1h")
                        .param("maxViews", "1"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("index"))
                .andExpect(model().attribute("error", Matchers.containsString("64 KiB")));

        verifyNoInteractions(secretService);
    }

    @Test
    @DisplayName("AC-005 / AF-03 / BR-002: TTL no permitido rechaza con 400")
    void invalidTtlRejectsWith400() throws Exception {
        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "Valid secret")
                        .param("ttl", "999years")
                        .param("maxViews", "1"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("index"))
                .andExpect(model().attributeExists("error"));

        verifyNoInteractions(secretService);
    }

    @Test
    @DisplayName("AC-006 / AF-03 / BR-003: maxViews fuera de rango (1 a 10) rechaza con 400")
    void invalidMaxViewsRejectsWith400() throws Exception {
        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "Valid secret")
                        .param("ttl", "1h")
                        .param("maxViews", "0"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("index"));

        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "Valid secret")
                        .param("ttl", "1h")
                        .param("maxViews", "15"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("index"));

        verifyNoInteractions(secretService);
    }

    @Test
    @DisplayName("AC-007 / BR-006: secret-created contiene cabeceras anti-almacenamiento")
    void secretCreatedIncludesAntiCacheHeaders() throws Exception {
        UUID secretId = UUID.randomUUID();
        CreateSecretResult result = new CreateSecretResult(secretId, "token-abc", "hash", Instant.parse("2026-11-09T12:00:00Z"));
        when(secretService.createSecret(any())).thenReturn(result);

        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "Valid secret content")
                        .param("ttl", "5m")
                        .param("maxViews", "2"))
                .andExpect(header().string("Cache-Control", Matchers.containsString("no-store")))
                .andExpect(header().string("X-Robots-Tag", "noindex, nofollow"));
    }

    @Test
    @WithMockUser(username = "11111111-2222-3333-4444-555555555555")
    @DisplayName("AC-008 / BR-007: Usuario autenticado asocia su UUID como owner_user_id")
    void authenticatedUserAttributedAsOwner() throws Exception {
        UUID secretId = UUID.randomUUID();
        CreateSecretResult result = new CreateSecretResult(secretId, "auth-token-123", "hash", Instant.parse("2026-11-09T12:00:00Z"));
        when(secretService.createSecret(any())).thenReturn(result);

        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "Secret owned by user")
                        .param("ttl", "1d")
                        .param("maxViews", "1"))
                .andExpect(status().isOk());

        verify(secretService).createSecret(argThat(cmd ->
                UUID.fromString("11111111-2222-3333-4444-555555555555").equals(cmd.ownerUserId())
        ));
    }
}
