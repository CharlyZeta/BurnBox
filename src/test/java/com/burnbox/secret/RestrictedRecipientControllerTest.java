package com.burnbox.secret;

import com.burnbox.crypto.CryptoTokenService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RestrictedRecipientControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SecretService secretService;

    private final CryptoTokenService tokenService = new CryptoTokenService();
    private final String validToken = "A".repeat(43);

    @Test
    @DisplayName("GET /s/{token} anónimo sobre secreto restringido renderiza reveal-login-required")
    void anonymousGetRestrictedSecretRendersLoginRequired() throws Exception {
        when(secretService.checkAccess(anyString(), isNull(), eq(false)))
                .thenReturn(new SecretAccessResult.RecipientLoginRequired());

        mockMvc.perform(get("/s/" + validToken))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-login-required"))
                .andExpect(header().string("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"));
    }

    @Test
    @DisplayName("GET /s/{token} con usuario coincidente renderiza reveal-intermediate")
    @WithMockUser(username = "alice@burnbox.io")
    void matchingUserGetRestrictedSecretRendersIntermediate() throws Exception {
        when(secretService.checkAccess(anyString(), eq("alice@burnbox.io"), eq(true)))
                .thenReturn(new SecretAccessResult.Success(new byte[0], 0, 1, SecretState.ACTIVE));

        mockMvc.perform(get("/s/" + validToken))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-intermediate"))
                .andExpect(cookie().exists(RevealController.CSRF_COOKIE_NAME));
    }

    @Test
    @DisplayName("GET /s/{token} con usuario no coincidente renderiza reveal-unavailable (indistinguibilidad)")
    @WithMockUser(username = "bob@burnbox.io")
    void mismatchingUserGetRestrictedSecretRendersUnavailable() throws Exception {
        when(secretService.checkAccess(anyString(), eq("bob@burnbox.io"), eq(true)))
                .thenReturn(new SecretAccessResult.NotAvailable("Secret unavailable"));

        mockMvc.perform(get("/s/" + validToken))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-unavailable"));
    }

    @Test
    @DisplayName("POST /s/{token}/reveal con usuario coincidente revela contenido exitosamente")
    @WithMockUser(username = "alice@burnbox.io")
    void matchingUserPostRevealSucceeds() throws Exception {
        String csrf = tokenService.generateToken();
        byte[] payload = "SuperSecretRevealed".getBytes(StandardCharsets.UTF_8);

        when(secretService.consumeSecret(anyString(), isNull(), eq("alice@burnbox.io"), eq(true)))
                .thenReturn(new SecretAccessResult.Success(payload, 1, 1, SecretState.CONSUMED));

        mockMvc.perform(post("/s/" + validToken + "/reveal")
                        .cookie(new Cookie(RevealController.CSRF_COOKIE_NAME, csrf))
                        .param("_csrf", csrf))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-content"))
                .andExpect(model().attribute("content", "SuperSecretRevealed"));
    }

    @Test
    @DisplayName("POST /secrets con recipientEmail inválido responde 400 Bad Request")
    void createSecretWithInvalidEmailReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("content", "Confidential message")
                        .param("ttl", "1h")
                        .param("maxViews", "1")
                        .param("recipientEmail", "not-an-email"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("index"))
                .andExpect(model().attribute("error", "El formato del email de destinatario es inválido"));
    }
}
