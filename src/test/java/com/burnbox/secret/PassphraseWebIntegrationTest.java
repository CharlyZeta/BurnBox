package com.burnbox.secret;

import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.platform.SecurityConfig;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = {SecretWebController.class, RevealController.class})
@Import(SecurityConfig.class)
class PassphraseWebIntegrationTest {

    private static final String SAMPLE_TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v";
    private static final String CSRF_COOKIE = "burnbox_reveal_csrf";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SecretService secretService;

    @MockitoBean
    private CryptoTokenService tokenService;

    @Test
    @DisplayName("AC-001 & AC-003: Revelar secreto con passphrase sin enviarla renderiza formulario de contraseña")
    void revealWithoutPassphraseRendersPassphrasePrompt() throws Exception {
        when(tokenService.hashToken(eq(SAMPLE_TOKEN))).thenReturn("hash-123");
        when(secretService.consumeSecret(eq("hash-123")))
                .thenReturn(new SecretAccessResult.PassphraseRequired());

        mockMvc.perform(post("/s/" + SAMPLE_TOKEN + "/reveal")
                        .cookie(new jakarta.servlet.http.Cookie(CSRF_COOKIE, "match-token"))
                        .param("_csrf", "match-token"))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-passphrase"))
                .andExpect(content().string(Matchers.containsString("Contraseña requerida")))
                .andExpect(content().string(Matchers.containsString("name=\"passphrase\"")));
    }

    @Test
    @DisplayName("AC-004: Enviar contraseña correcta renderiza el contenido del secreto")
    void submitCorrectPassphraseRevealsContent() throws Exception {
        byte[] payload = "Super secret decoded plaintext".getBytes(StandardCharsets.UTF_8);
        when(tokenService.hashToken(eq(SAMPLE_TOKEN))).thenReturn("hash-123");
        when(secretService.consumeSecret(eq("hash-123"), eq("correct-pass-123")))
                .thenReturn(new SecretAccessResult.Success(payload, 1, 1, SecretState.CONSUMED));

        mockMvc.perform(post("/s/" + SAMPLE_TOKEN + "/reveal")
                        .cookie(new jakarta.servlet.http.Cookie(CSRF_COOKIE, "match-token"))
                        .param("_csrf", "match-token")
                        .param("passphrase", "correct-pass-123"))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-content"))
                .andExpect(content().string(Matchers.containsString("Super secret decoded plaintext")));
    }

    @Test
    @DisplayName("AC-005 & AF-01: Enviar contraseña incorrecta muestra alerta con intentos restantes")
    void submitWrongPassphraseShowsRemainingAttempts() throws Exception {
        when(tokenService.hashToken(eq(SAMPLE_TOKEN))).thenReturn("hash-123");
        when(secretService.consumeSecret(eq("hash-123"), eq("bad-pass")))
                .thenReturn(new SecretAccessResult.WrongPassphrase(4));

        mockMvc.perform(post("/s/" + SAMPLE_TOKEN + "/reveal")
                        .cookie(new jakarta.servlet.http.Cookie(CSRF_COOKIE, "match-token"))
                        .param("_csrf", "match-token")
                        .param("passphrase", "bad-pass"))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-passphrase"))
                .andExpect(content().string(Matchers.containsString("Le quedan 4 intento(s)")));
    }

    @Test
    @DisplayName("AC-006, AC-007 & AF-02: Destrucción por quinto fallo retorna vista no disponible")
    void fiveFailuresReturnsUnavailableView() throws Exception {
        when(tokenService.hashToken(eq(SAMPLE_TOKEN))).thenReturn("hash-123");
        when(secretService.consumeSecret(eq("hash-123"), eq("bad-pass-5")))
                .thenReturn(new SecretAccessResult.NotAvailable("DESTROYED_BY_ABUSE"));

        mockMvc.perform(post("/s/" + SAMPLE_TOKEN + "/reveal")
                        .cookie(new jakarta.servlet.http.Cookie(CSRF_COOKIE, "match-token"))
                        .param("_csrf", "match-token")
                        .param("passphrase", "bad-pass-5"))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-unavailable"));
    }

    @Test
    @DisplayName("AC-002 & AF-03: Creación de secreto con passphrase menor a 8 caracteres retorna 400")
    void invalidPassphraseLengthRejectsWith400() throws Exception {
        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .param("content", "Valid payload text")
                        .param("ttl", "1h")
                        .param("maxViews", "1")
                        .param("passphrase", "short"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("index"))
                .andExpect(model().attribute("error", Matchers.containsString("entre 8 y 128 caracteres")));
    }
}
