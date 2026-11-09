package com.burnbox.session;

import com.burnbox.identity.AppUser;
import com.burnbox.identity.BurnboxOidcUser;
import com.burnbox.identity.UserStatus;
import com.burnbox.platform.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = SessionManagementController.class)
@Import(SecurityConfig.class)
class SessionManagementControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserSessionService sessionService;

    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    private BurnboxOidcUser createMockUser(UUID userId, String email) {
        AppUser appUser = new AppUser(
                userId, "Test User", email, true,
                UserStatus.ACTIVE, null, "es", fixedTime, fixedTime
        );
        OidcIdToken idToken = new OidcIdToken("mock-token", fixedTime, fixedTime.plusSeconds(3600), Map.of(
                "sub", "sub-123",
                "email", email
        ));
        DefaultOidcUser rawOidc = new DefaultOidcUser(Collections.emptyList(), idToken);
        return new BurnboxOidcUser(rawOidc, appUser);
    }

    @Test
    @DisplayName("AC-004: GET /account/sessions lista sesiones activas del usuario autenticado")
    void listSessionsRendersAccountSessionsPage() throws Exception {
        UUID userId = UUID.randomUUID();
        BurnboxOidcUser user = createMockUser(userId, "user@burnbox.io");

        UserSessionMeta session = new UserSessionMeta(
                UUID.randomUUID(), "sess-mock-1", userId, "ip-hash-1234567890", "Chrome on Linux",
                fixedTime, fixedTime, false
        );

        when(sessionService.listActiveSessions(userId)).thenReturn(List.of(session));

        mockMvc.perform(get("/account/sessions")
                        .with(SecurityMockMvcRequestPostProcessors.authentication(
                                new org.springframework.security.authentication.TestingAuthenticationToken(user, null)
                        )))
                .andExpect(status().isOk())
                .andExpect(view().name("account-sessions"))
                .andExpect(content().string(containsString("Gestión de Sesiones")))
                .andExpect(content().string(containsString("Chrome on Linux")));
    }

    @Test
    @DisplayName("AF-04: Usuario no autenticado es redirigido a /login")
    void unauthenticatedRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/account/sessions"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    @DisplayName("AC-005: POST /account/sessions/{id}/revoke revoca la sesión y redirige")
    void revokeSessionEndpointCallsServiceAndRedirects() throws Exception {
        UUID userId = UUID.randomUUID();
        BurnboxOidcUser user = createMockUser(userId, "user@burnbox.io");

        mockMvc.perform(post("/account/sessions/{id}/revoke", "sess-remote")
                        .with(SecurityMockMvcRequestPostProcessors.authentication(
                                new org.springframework.security.authentication.TestingAuthenticationToken(user, null)
                        ))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/sessions?revoked=true"));

        verify(sessionService).revokeSession(eq(userId), eq("sess-remote"));
    }

    @Test
    @DisplayName("AC-006: POST /account/sessions/revoke-others revoca las demás sesiones")
    void revokeOthersEndpointCallsServiceAndRedirects() throws Exception {
        UUID userId = UUID.randomUUID();
        BurnboxOidcUser user = createMockUser(userId, "user@burnbox.io");
        MockHttpSession mockSession = new MockHttpSession(null, "current-session-id");

        mockMvc.perform(post("/account/sessions/revoke-others")
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.authentication(
                                new org.springframework.security.authentication.TestingAuthenticationToken(user, null)
                        ))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/sessions?revokedOthers=true"));

        verify(sessionService).revokeOtherSessions(eq(userId), eq("current-session-id"));
    }
}
