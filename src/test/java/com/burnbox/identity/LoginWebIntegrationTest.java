package com.burnbox.identity;

import com.burnbox.platform.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = LoginController.class)
@Import(SecurityConfig.class)
class LoginWebIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Main Flow / AC-001: GET /login muestra los botones de OAuth2 para Google y Microsoft")
    void loginPageRendersProviderButtons() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("Continuar con Google")))
                .andExpect(content().string(containsString("Continuar con Microsoft")))
                .andExpect(content().string(containsString("/oauth2/authorization/google")))
                .andExpect(content().string(containsString("/oauth2/authorization/microsoft")));
    }

    @Test
    @DisplayName("AF-03 / AC-005: GET /login?error=collision muestra la vista de colisión nOAuth")
    void collisionRendersCollisionPage() throws Exception {
        mockMvc.perform(get("/login").param("error", "collision"))
                .andExpect(status().isOk())
                .andExpect(view().name("login-collision"))
                .andExpect(content().string(containsString("Cuenta Existente Detectada")))
                .andExpect(content().string(containsString("nOAuth / Pre-Account Takeover")));
    }

    @Test
    @DisplayName("AC-006 / AF-04: POST /logout con token CSRF invalida la sesión y redirige a la raíz")
    void logoutInvalidatesSession() throws Exception {
        mockMvc.perform(post("/logout")
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(cookie().maxAge("JSESSIONID", 0));
    }
}
