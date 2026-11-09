package com.burnbox.secret;

import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.platform.SecurityConfig;
import jakarta.servlet.http.Cookie;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = RevealController.class)
@Import(SecurityConfig.class)
class RevealControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SecretService secretService;

    @MockitoBean
    private CryptoTokenService tokenService;

    private final String validToken = "abc123DEF456_-abc123DEF456_-abc123DEF456_--";
    private final String validHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    @DisplayName("AC-001 / AF-01 / BR-001: GET /s/{token} responde 200 con vista intermedia y no consume el secreto")
    void getIntermediatePageDoesNotConsumeSecret() throws Exception {
        when(tokenService.generateToken()).thenReturn("csrf-test-token-1234");

        mockMvc.perform(get("/s/{token}", validToken))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-intermediate"))
                .andExpect(model().attribute("token", validToken))
                .andExpect(model().attribute("csrfToken", "csrf-test-token-1234"))
                .andExpect(cookie().exists(RevealController.CSRF_COOKIE_NAME))
                .andExpect(header().string("Cache-Control", Matchers.containsString("no-store")))
                .andExpect(header().string("X-Robots-Tag", "noindex, nofollow"));

        // Se verifica que NUNCA se invoca al servicio de consumo en un GET (BR-001)
        verifyNoInteractions(secretService);
    }

    @Test
    @DisplayName("AC-002 / BR-003: Vista intermedia incluye cookie SameSite=Strict y valor coincidente")
    void intermediateIncludesSameSiteCookie() throws Exception {
        when(tokenService.generateToken()).thenReturn("csrf-token-strict");

        mockMvc.perform(get("/s/{token}", validToken))
                .andExpect(status().isOk())
                .andExpect(cookie().value(RevealController.CSRF_COOKIE_NAME, "csrf-token-strict"))
                .andExpect(cookie().path(RevealController.CSRF_COOKIE_NAME, "/s/"))
                .andExpect(cookie().httpOnly(RevealController.CSRF_COOKIE_NAME, true));
    }

    @Test
    @DisplayName("AC-003 / BR-002 / BR-004: POST /s/{token}/reveal con CSRF válido consume y renderiza contenido")
    void postRevealWithValidCsrfConsumesAndShowsContent() throws Exception {
        String csrf = "valid-csrf-token";
        byte[] payload = "SuperSecretRevealedData".getBytes(StandardCharsets.UTF_8);

        when(tokenService.hashToken(validToken)).thenReturn(validHash);
        when(secretService.consumeSecret(validHash)).thenReturn(
                new SecretAccessResult.Success(payload, 1, 1, SecretState.CONSUMED)
        );

        mockMvc.perform(post("/s/{token}/reveal", validToken)
                        .cookie(new Cookie(RevealController.CSRF_COOKIE_NAME, csrf))
                        .param("_csrf", csrf))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-content"))
                .andExpect(model().attribute("content", "SuperSecretRevealedData"))
                .andExpect(model().attribute("views", 1))
                .andExpect(model().attribute("maxViews", 1))
                .andExpect(model().attribute("state", SecretState.CONSUMED))
                .andExpect(header().string("Cache-Control", Matchers.containsString("no-store")))
                .andExpect(header().string("X-Robots-Tag", "noindex, nofollow"));

        verify(secretService).consumeSecret(validHash);
    }

    @Test
    @DisplayName("AC-004 / AF-02: POST sin CSRF o con token discordante devuelve 403 y no consume")
    void postWithoutMatchingCsrfReturns403() throws Exception {
        // Caso 1: Sin cookie ni param
        mockMvc.perform(post("/s/{token}/reveal", validToken))
                .andExpect(status().isForbidden());

        // Caso 2: Cookie y param discordantes
        mockMvc.perform(post("/s/{token}/reveal", validToken)
                        .cookie(new Cookie(RevealController.CSRF_COOKIE_NAME, "token-in-cookie"))
                        .param("_csrf", "different-token-in-form"))
                .andExpect(status().isForbidden());

        verifyNoInteractions(secretService);
    }

    @Test
    @DisplayName("AC-005 / AF-03 / BR-005: Respuestas para secreto inexistente, vencido o consumido son uniformes")
    void unavailableResponsesAreUniform() throws Exception {
        String csrf = "csrf-token-xyz";
        when(tokenService.hashToken(anyString())).thenReturn(validHash);

        // Caso Inexistente / Vencido / Consumido retornan NotAvailable
        when(secretService.consumeSecret(validHash)).thenReturn(
                new SecretAccessResult.NotAvailable("Reason does not matter")
        );

        var mvcResult = mockMvc.perform(post("/s/{token}/reveal", validToken)
                        .cookie(new Cookie(RevealController.CSRF_COOKIE_NAME, csrf))
                        .param("_csrf", csrf))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-unavailable"))
                .andExpect(header().string("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"))
                .andExpect(header().string("X-Robots-Tag", "noindex, nofollow"))
                .andReturn();

        String htmlContent = mvcResult.getResponse().getContentAsString();
        assertThat(htmlContent).contains("Secreto no disponible");
    }

    @Test
    @DisplayName("AC-006 / BR-006: Cabeceras anti-almacenamiento y anti-indexación en todas las respuestas")
    void antiCacheAndRobotsHeadersPresentOnAllResponses() throws Exception {
        mockMvc.perform(get("/s/{token}", validToken))
                .andExpect(header().string("Cache-Control", Matchers.containsString("no-store")))
                .andExpect(header().string("X-Robots-Tag", "noindex, nofollow"));
    }

    @Test
    @DisplayName("AC-007 / AF-04 / BR-007: Contenido con scripts HTML se escapa como texto literal contra XSS")
    void xssPayloadIsEscapedAsPlainText() throws Exception {
        String csrf = "csrf-xss";
        String maliciousPayload = "<script>alert('xss');</script>";

        when(tokenService.hashToken(validToken)).thenReturn(validHash);
        when(secretService.consumeSecret(validHash)).thenReturn(
                new SecretAccessResult.Success(maliciousPayload.getBytes(StandardCharsets.UTF_8), 1, 1, SecretState.CONSUMED)
        );

        var result = mockMvc.perform(post("/s/{token}/reveal", validToken)
                        .cookie(new Cookie(RevealController.CSRF_COOKIE_NAME, csrf))
                        .param("_csrf", csrf))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-content"))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        // Debe estar escapado en HTML como &lt;script&gt; y no aparecer ejecutable sin escapar
        assertThat(body).contains("&lt;script&gt;alert(&#39;xss&#39;);&lt;/script&gt;");
        assertThat(body).doesNotContain("<script>alert('xss');</script>");
    }
}
