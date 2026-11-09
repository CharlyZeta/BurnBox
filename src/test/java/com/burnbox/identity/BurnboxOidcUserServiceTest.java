package com.burnbox.identity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BurnboxOidcUserServiceTest {

    @Mock
    private UserProvisioningService provisioningService;

    private BurnboxOidcUserService oidcUserService;
    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    @BeforeEach
    void setUp() {
        oidcUserService = new BurnboxOidcUserService(provisioningService);
    }

    private OidcUser createMockOidcUser(String issuer, String sub, String email, boolean emailVerified) {
        OidcIdToken idToken = new OidcIdToken(
                "mock-token-value",
                fixedTime,
                fixedTime.plusSeconds(3600),
                Map.of(
                        "iss", issuer,
                        "sub", sub,
                        "email", email,
                        "email_verified", emailVerified,
                        "name", "Test User"
                )
        );
        return new DefaultOidcUser(Collections.emptyList(), idToken);
    }

    @Test
    @DisplayName("Main Flow / AC-001: Procesa usuario exitosamente cuando provisioning resulta en Success")
    void processesOidcUserSuccessfully() {
        OidcUser rawOidcUser = createMockOidcUser("https://accounts.google.com", "sub-123", "alice@burnbox.io", true);

        AppUser appUser = new AppUser(
                UUID.randomUUID(), "Alice", "alice@burnbox.io", true,
                UserStatus.ACTIVE, null, "es", fixedTime, fixedTime
        );

        when(provisioningService.authenticateOrProvision(any()))
                .thenReturn(new ProvisioningResult.Success(appUser, true, false));

        BurnboxOidcUser result = oidcUserService.processOidcUser("google", rawOidcUser);

        assertThat(result).isNotNull();
        assertThat(result.getAppUser()).isEqualTo(appUser);
        assertThat(result.getEmail()).isEqualTo("alice@burnbox.io");
    }

    @Test
    @DisplayName("AC-003 / AF-01: Lanza OAuth2AuthenticationException si usuario está DISABLED")
    void throwsExceptionWhenUserDisabled() {
        OidcUser rawOidcUser = createMockOidcUser("https://accounts.google.com", "sub-disabled", "disabled@burnbox.io", true);

        when(provisioningService.authenticateOrProvision(any()))
                .thenReturn(new ProvisioningResult.RejectedDisabled("Cuenta inhabilitada"));

        assertThatThrownBy(() -> oidcUserService.processOidcUser("google", rawOidcUser))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .extracting(e -> ((OAuth2AuthenticationException) e).getError().getErrorCode())
                .isEqualTo("account_disabled");
    }

    @Test
    @DisplayName("AC-005 / AF-03: Lanza OAuth2AuthenticationException si ocurre colisión nOAuth")
    void throwsExceptionWhenCollisionDetected() {
        OidcUser rawOidcUser = createMockOidcUser("https://accounts.google.com", "sub-attacker", "target@burnbox.io", true);

        when(provisioningService.authenticateOrProvision(any()))
                .thenReturn(new ProvisioningResult.CollisionBlocked("target@burnbox.io", "google"));

        assertThatThrownBy(() -> oidcUserService.processOidcUser("google", rawOidcUser))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .extracting(e -> ((OAuth2AuthenticationException) e).getError().getErrorCode())
                .isEqualTo("email_collision");
    }
}
