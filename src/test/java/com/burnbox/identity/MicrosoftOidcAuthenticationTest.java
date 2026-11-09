package com.burnbox.identity;

import com.burnbox.platform.SecurityEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MicrosoftOidcAuthenticationTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    @Mock
    private SecurityEventPublisher securityEventPublisher;

    private Clock clock;
    private UserProvisioningService provisioningService;
    private BurnboxOidcUserService oidcUserService;
    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(fixedTime, ZoneOffset.UTC);
        provisioningService = new UserProvisioningService(
                userRepository,
                applicationEventPublisher,
                securityEventPublisher,
                clock
        );
        oidcUserService = new BurnboxOidcUserService(provisioningService);
    }

    private OidcUser createMicrosoftOidcUser(String tid, String sub, String email, Boolean emailVerified, String name) {
        String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", sub);
        claims.put("tid", tid);
        if (email != null) {
            claims.put("email", email);
            claims.put("preferred_username", email);
        }
        if (emailVerified != null) {
            claims.put("email_verified", emailVerified);
        }
        if (name != null) {
            claims.put("name", name);
        }

        OidcIdToken idToken = new OidcIdToken("mock-ms-token", fixedTime, fixedTime.plusSeconds(3600), claims);
        return new DefaultOidcUser(Collections.emptyList(), idToken);
    }

    @Test
    @DisplayName("AC-001 / BR-003: Login con Microsoft con issuer de tenant válido aprovisiona exitosamente")
    void microsoftLoginWithValidTenantProvisionsSuccessfully() {
        String tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";
        OidcUser msUser = createMicrosoftOidcUser(tid, "ms-sub-001", "carol@contoso.com", true, "Carol Danvers");

        when(userRepository.findIdentity(issuer, "ms-sub-001")).thenReturn(Optional.empty());
        when(userRepository.findByVerifiedEmail("carol@contoso.com")).thenReturn(Optional.empty());

        BurnboxOidcUser user = oidcUserService.processOidcUser("microsoft", msUser);

        assertThat(user).isNotNull();
        assertThat(user.getAppUser().status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(user.getAppUser().displayName()).isEqualTo("Carol Danvers");

        ArgumentCaptor<LinkedIdentity> identityCaptor = ArgumentCaptor.forClass(LinkedIdentity.class);
        verify(userRepository).insertIdentity(identityCaptor.capture());
        LinkedIdentity identity = identityCaptor.getValue();
        assertThat(identity.provider()).isEqualTo(IdentityProvider.MICROSOFT);
        assertThat(identity.issuer()).isEqualTo(issuer);
        assertThat(identity.subject()).isEqualTo("ms-sub-001");
    }

    @Test
    @DisplayName("AC-003 / AF-02 / BR-002: Cuenta Microsoft sin email_verified explícito se crea como no verificada sin bloquear colisiones")
    void unverifiedEmailRegistersAsUnverifiedWithoutCollision() {
        String tid = "9188040d-6c67-4c5b-b112-36a304b66dad"; // Consumer tenant
        String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";
        // email_verified is null (missing in Microsoft consumer accounts)
        OidcUser msUser = createMicrosoftOidcUser(tid, "ms-sub-unverified", "unverified@outlook.com", null, "Unverified User");

        when(userRepository.findIdentity(issuer, "ms-sub-unverified")).thenReturn(Optional.empty());

        BurnboxOidcUser user = oidcUserService.processOidcUser("microsoft", msUser);

        assertThat(user).isNotNull();
        assertThat(user.getAppUser().primaryEmailVerified()).isFalse();

        // Must never query findByVerifiedEmail because claims.emailVerified() is false
        verify(userRepository, never()).findByVerifiedEmail(any());
        verify(userRepository).insertUser(any());
        verify(userRepository).insertIdentity(any());
    }

    @Test
    @DisplayName("AC-004 / AF-04 / BR-002: Colisión de email verificado de Microsoft con usuario existente bloquea auto-merge (nOAuth)")
    void verifiedEmailCollisionRejectsAutoMerge() {
        String tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";
        OidcUser msUser = createMicrosoftOidcUser(tid, "ms-sub-attacker", "victim@burnbox.io", true, "Attacker");

        AppUser existingUser = new AppUser(
                UUID.randomUUID(), "Victim", "victim@burnbox.io", true,
                UserStatus.ACTIVE, null, "es", fixedTime, fixedTime
        );

        when(userRepository.findIdentity(issuer, "ms-sub-attacker")).thenReturn(Optional.empty());
        when(userRepository.findByVerifiedEmail("victim@burnbox.io")).thenReturn(Optional.of(existingUser));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> oidcUserService.processOidcUser("microsoft", msUser))
                .isInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class)
                .extracting(e -> ((org.springframework.security.oauth2.core.OAuth2AuthenticationException) e).getError().getErrorCode())
                .isEqualTo("email_collision");

        verify(userRepository, never()).insertUser(any());
        verify(userRepository, never()).insertIdentity(any());
        verify(applicationEventPublisher).publishEvent(any(LoginRejected.class));
    }

    @Test
    @DisplayName("AC-005 / BR-004: Usuario Microsoft existente actualiza last_login_at y last_used_at")
    void existingMicrosoftUserUpdatesLastLogin() {
        String tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();

        AppUser existingUser = new AppUser(
                userId, "Existing MS User", "user@ms.com", true,
                UserStatus.ACTIVE, null, "es", fixedTime.minusSeconds(1000), fixedTime.minusSeconds(1000)
        );
        LinkedIdentity existingIdentity = new LinkedIdentity(
                identityId, userId, IdentityProvider.MICROSOFT, issuer,
                "ms-sub-existing", "user@ms.com", true, fixedTime.minusSeconds(1000), fixedTime.minusSeconds(1000)
        );

        OidcUser msUser = createMicrosoftOidcUser(tid, "ms-sub-existing", "user@ms.com", true, "Existing MS User");

        when(userRepository.findIdentity(issuer, "ms-sub-existing")).thenReturn(Optional.of(existingIdentity));
        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));

        BurnboxOidcUser user = oidcUserService.processOidcUser("microsoft", msUser);

        assertThat(user).isNotNull();
        verify(userRepository).updateLastLogin(userId, fixedTime);
        verify(userRepository).updateIdentityLastUsed(identityId, fixedTime);
        verify(applicationEventPublisher).publishEvent(any(UserLoggedIn.class));
    }

    @Test
    @DisplayName("AC-006 / AF-03 / BR-004: Usuario Microsoft en estado DISABLED es rechazado emitiendo LoginRejected")
    void disabledMicrosoftUserIsRejected() {
        String tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();

        AppUser disabledUser = new AppUser(
                userId, "Disabled MS User", "disabled@ms.com", true,
                UserStatus.DISABLED, null, "es", fixedTime.minusSeconds(1000), fixedTime.minusSeconds(1000)
        );
        LinkedIdentity existingIdentity = new LinkedIdentity(
                identityId, userId, IdentityProvider.MICROSOFT, issuer,
                "ms-sub-disabled", "disabled@ms.com", true, fixedTime.minusSeconds(1000), fixedTime.minusSeconds(1000)
        );

        OidcUser msUser = createMicrosoftOidcUser(tid, "ms-sub-disabled", "disabled@ms.com", true, "Disabled MS User");

        when(userRepository.findIdentity(issuer, "ms-sub-disabled")).thenReturn(Optional.of(existingIdentity));
        when(userRepository.findById(userId)).thenReturn(Optional.of(disabledUser));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> oidcUserService.processOidcUser("microsoft", msUser))
                .isInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class)
                .extracting(e -> ((org.springframework.security.oauth2.core.OAuth2AuthenticationException) e).getError().getErrorCode())
                .isEqualTo("account_disabled");

        verify(applicationEventPublisher).publishEvent(any(LoginRejected.class));
    }
}
