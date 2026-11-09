package com.burnbox.passkey;

import com.burnbox.identity.AppUser;
import com.burnbox.identity.BurnboxOidcUser;
import com.burnbox.identity.UserStatus;
import com.burnbox.platform.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Collections;
import java.util.HexFormat;
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

@WebMvcTest(controllers = PasskeyController.class)
@Import(SecurityConfig.class)
class PasskeyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private PasskeyService passkeyService;

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
    @DisplayName("Main Flow: GET /account/passkeys lista passkeys del usuario autenticado")
    void listPasskeysRendersAccountPasskeysPage() throws Exception {
        UUID userId = UUID.randomUUID();
        BurnboxOidcUser user = createMockUser(userId, "user@burnbox.io");

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(), userId, new byte[]{1, 2, 3, 4}, new byte[]{5, 6},
                10, "internal", "TouchID Pro", PasskeyState.ACTIVE, null, fixedTime, null
        );

        when(passkeyService.listPasskeys(userId)).thenReturn(List.of(cred));

        mockMvc.perform(get("/account/passkeys")
                        .with(SecurityMockMvcRequestPostProcessors.authentication(
                                new org.springframework.security.authentication.TestingAuthenticationToken(user, null)
                        )))
                .andExpect(status().isOk())
                .andExpect(view().name("account-passkeys"))
                .andExpect(content().string(containsString("Mis Passkeys")))
                .andExpect(content().string(containsString("TouchID Pro")));
    }

    @Test
    @DisplayName("AF-04: Usuario no autenticado es redirigido a /login")
    void unauthenticatedRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/account/passkeys"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    @DisplayName("AC-006: POST /account/passkeys/{idHex}/revoke revoca la passkey")
    void revokePasskeyEndpointCallsServiceAndRedirects() throws Exception {
        UUID userId = UUID.randomUUID();
        BurnboxOidcUser user = createMockUser(userId, "user@burnbox.io");
        byte[] credId = new byte[]{0x12, 0x34, 0x56, 0x78};
        String hex = HexFormat.of().formatHex(credId);

        mockMvc.perform(post("/account/passkeys/{hex}/revoke", hex)
                        .with(SecurityMockMvcRequestPostProcessors.authentication(
                                new org.springframework.security.authentication.TestingAuthenticationToken(user, null)
                        ))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/passkeys?revoked=true"));

        verify(passkeyService).revokePasskey(eq(userId), eq(credId));
    }
}
