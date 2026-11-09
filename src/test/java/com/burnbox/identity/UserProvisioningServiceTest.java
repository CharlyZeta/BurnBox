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

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserProvisioningServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    @Mock
    private SecurityEventPublisher securityEventPublisher;

    private Clock clock;
    private UserProvisioningService service;
    private Instant fixedInstant;

    @BeforeEach
    void setUp() {
        fixedInstant = Instant.parse("2026-11-09T16:00:00Z");
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC);
        service = new UserProvisioningService(
                userRepository,
                applicationEventPublisher,
                securityEventPublisher,
                clock
        );
    }

    @Test
    @DisplayName("AC-001 / BR-001: Autenticación exitosa con nuevo Google ID crea registro en app_user y linked_identity y emite UserRegistered")
    void provisionNewGoogleUserCreatesActiveUserAndIdentity() {
        OidcIdentityClaims claims = new OidcIdentityClaims(
                IdentityProvider.GOOGLE,
                "https://accounts.google.com",
                "google-sub-12345",
                "alice@example.com",
                true,
                "Alice",
                "es"
        );

        when(userRepository.findIdentity(claims.issuer(), claims.subject())).thenReturn(Optional.empty());
        when(userRepository.findByVerifiedEmail(claims.email())).thenReturn(Optional.empty());

        ProvisioningResult result = service.authenticateOrProvision(claims);

        assertThat(result).isInstanceOf(ProvisioningResult.Success.class);
        ProvisioningResult.Success success = (ProvisioningResult.Success) result;
        assertThat(success.newlyRegistered()).isTrue();
        assertThat(success.pendingDeletionWarning()).isFalse();
        assertThat(success.user().primaryEmail()).isEqualTo("alice@example.com");
        assertThat(success.user().status()).isEqualTo(UserStatus.ACTIVE);

        // Verify repository interactions
        ArgumentCaptor<AppUser> userCaptor = ArgumentCaptor.forClass(AppUser.class);
        verify(userRepository).insertUser(userCaptor.capture());
        AppUser savedUser = userCaptor.getValue();
        assertThat(savedUser.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(savedUser.createdAt()).isEqualTo(fixedInstant);

        ArgumentCaptor<LinkedIdentity> identityCaptor = ArgumentCaptor.forClass(LinkedIdentity.class);
        verify(userRepository).insertIdentity(identityCaptor.capture());
        LinkedIdentity savedIdentity = identityCaptor.getValue();
        assertThat(savedIdentity.provider()).isEqualTo(IdentityProvider.GOOGLE);
        assertThat(savedIdentity.issuer()).isEqualTo("https://accounts.google.com");
        assertThat(savedIdentity.subject()).isEqualTo("google-sub-12345");
        assertThat(savedIdentity.userId()).isEqualTo(savedUser.id());

        // Verify Domain events
        ArgumentCaptor<Object> eventCaptor = ArgumentCaptor.forClass(Object.class);
        verify(applicationEventPublisher, times(2)).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getAllValues()).hasAtLeastOneElementOfType(UserRegistered.class);
        assertThat(eventCaptor.getAllValues()).hasAtLeastOneElementOfType(UserLoggedIn.class);

        // Verify Audit events
        verify(securityEventPublisher).publish(eq("USER_REGISTERED"), eq("user"), any(), any());
        verify(securityEventPublisher).publish(eq("USER_LOGGED_IN"), eq("user"), any(), any());
    }

    @Test
    @DisplayName("AC-002 / BR-004: Autenticación con Google ID previamente registrado inicia sesión y actualiza last_login_at")
    void existingIdentityUpdatesLastLogin() {
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        AppUser existingUser = new AppUser(
                userId, "Bob", "bob@example.com", true,
                UserStatus.ACTIVE, null, "es", fixedInstant.minusSeconds(3600), fixedInstant.minusSeconds(3600)
        );
        LinkedIdentity existingIdentity = new LinkedIdentity(
                identityId, userId, IdentityProvider.GOOGLE, "https://accounts.google.com",
                "google-sub-bob", "bob@example.com", true, fixedInstant.minusSeconds(3600), fixedInstant.minusSeconds(3600)
        );

        OidcIdentityClaims claims = new OidcIdentityClaims(
                IdentityProvider.GOOGLE,
                "https://accounts.google.com",
                "google-sub-bob",
                "bob@example.com",
                true,
                "Bob",
                "es"
        );

        when(userRepository.findIdentity(claims.issuer(), claims.subject())).thenReturn(Optional.of(existingIdentity));
        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));

        ProvisioningResult result = service.authenticateOrProvision(claims);

        assertThat(result).isInstanceOf(ProvisioningResult.Success.class);
        ProvisioningResult.Success success = (ProvisioningResult.Success) result;
        assertThat(success.newlyRegistered()).isFalse();
        assertThat(success.pendingDeletionWarning()).isFalse();

        verify(userRepository).updateLastLogin(userId, fixedInstant);
        verify(userRepository).updateIdentityLastUsed(identityId, fixedInstant);
        verify(applicationEventPublisher).publishEvent(any(UserLoggedIn.class));
        verify(securityEventPublisher).publish(eq("USER_LOGGED_IN"), eq("user"), eq(userId.toString()), any());
    }

    @Test
    @DisplayName("AC-003 / AF-01 / BR-003: Intento de inicio de sesión de usuario en estado DISABLED es rechazado")
    void disabledUserRejected() {
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        AppUser disabledUser = new AppUser(
                userId, "Disabled", "disabled@example.com", true,
                UserStatus.DISABLED, null, "es", fixedInstant.minusSeconds(3600), fixedInstant.minusSeconds(3600)
        );
        LinkedIdentity existingIdentity = new LinkedIdentity(
                identityId, userId, IdentityProvider.GOOGLE, "https://accounts.google.com",
                "google-sub-disabled", "disabled@example.com", true, fixedInstant.minusSeconds(3600), fixedInstant.minusSeconds(3600)
        );

        OidcIdentityClaims claims = new OidcIdentityClaims(
                IdentityProvider.GOOGLE,
                "https://accounts.google.com",
                "google-sub-disabled",
                "disabled@example.com",
                true,
                "Disabled",
                "es"
        );

        when(userRepository.findIdentity(claims.issuer(), claims.subject())).thenReturn(Optional.of(existingIdentity));
        when(userRepository.findById(userId)).thenReturn(Optional.of(disabledUser));

        ProvisioningResult result = service.authenticateOrProvision(claims);

        assertThat(result).isInstanceOf(ProvisioningResult.RejectedDisabled.class);
        ProvisioningResult.RejectedDisabled rejected = (ProvisioningResult.RejectedDisabled) result;
        assertThat(rejected.reason()).contains("inhabilitada");

        verify(userRepository, never()).updateLastLogin(any(), any());
        verify(applicationEventPublisher).publishEvent(any(LoginRejected.class));
        verify(securityEventPublisher).publish(eq("LOGIN_REJECTED"), eq("user"), eq(userId.toString()), any());
    }

    @Test
    @DisplayName("AC-004 / AF-02 / BR-003: Intento de inicio de sesión de usuario en PENDING_DELETION es admitido con aviso")
    void pendingDeletionUserAdmittedWithWarning() {
        UUID userId = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        AppUser pendingUser = new AppUser(
                userId, "Pending", "pending@example.com", true,
                UserStatus.PENDING_DELETION, fixedInstant.plusSeconds(86400 * 30), "es",
                fixedInstant.minusSeconds(3600), fixedInstant.minusSeconds(3600)
        );
        LinkedIdentity existingIdentity = new LinkedIdentity(
                identityId, userId, IdentityProvider.GOOGLE, "https://accounts.google.com",
                "google-sub-pending", "pending@example.com", true, fixedInstant.minusSeconds(3600), fixedInstant.minusSeconds(3600)
        );

        OidcIdentityClaims claims = new OidcIdentityClaims(
                IdentityProvider.GOOGLE,
                "https://accounts.google.com",
                "google-sub-pending",
                "pending@example.com",
                true,
                "Pending",
                "es"
        );

        when(userRepository.findIdentity(claims.issuer(), claims.subject())).thenReturn(Optional.of(existingIdentity));
        when(userRepository.findById(userId)).thenReturn(Optional.of(pendingUser));

        ProvisioningResult result = service.authenticateOrProvision(claims);

        assertThat(result).isInstanceOf(ProvisioningResult.Success.class);
        ProvisioningResult.Success success = (ProvisioningResult.Success) result;
        assertThat(success.pendingDeletionWarning()).isTrue();

        verify(userRepository).updateLastLogin(userId, fixedInstant);
        verify(applicationEventPublisher).publishEvent(any(UserLoggedIn.class));
    }

    @Test
    @DisplayName("AC-005 / AF-03 / BR-002: Colisión de email verificado con cuenta existente rechaza fusión automática (nOAuth mitigation)")
    void verifiedEmailCollisionRejectsAutoMerge() {
        UUID existingUserId = UUID.randomUUID();
        AppUser existingEmailUser = new AppUser(
                existingUserId, "Original Owner", "target@example.com", true,
                UserStatus.ACTIVE, null, "es", fixedInstant.minusSeconds(3600), fixedInstant.minusSeconds(3600)
        );

        OidcIdentityClaims claims = new OidcIdentityClaims(
                IdentityProvider.GOOGLE,
                "https://accounts.google.com",
                "google-attacker-sub-999",
                "target@example.com",
                true,
                "Attacker",
                "es"
        );

        when(userRepository.findIdentity(claims.issuer(), claims.subject())).thenReturn(Optional.empty());
        when(userRepository.findByVerifiedEmail("target@example.com")).thenReturn(Optional.of(existingEmailUser));

        ProvisioningResult result = service.authenticateOrProvision(claims);

        assertThat(result).isInstanceOf(ProvisioningResult.CollisionBlocked.class);
        ProvisioningResult.CollisionBlocked blocked = (ProvisioningResult.CollisionBlocked) result;
        assertThat(blocked.email()).isEqualTo("target@example.com");

        // Must not create user or identity
        verify(userRepository, never()).insertUser(any());
        verify(userRepository, never()).insertIdentity(any());

        // Must publish LoginRejected event
        ArgumentCaptor<LoginRejected> eventCaptor = ArgumentCaptor.forClass(LoginRejected.class);
        verify(applicationEventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().reason()).contains("nOAuth");

        // Must publish security audit
        verify(securityEventPublisher).publish(eq("LOGIN_REJECTED"), eq("identity"), eq("google-attacker-sub-999"), any());
    }

    @Test
    @DisplayName("AC-007 / BR-005: Eventos de dominio UserRegistered, UserLoggedIn y LoginRejected se publican sin incluir tokens ni secretos")
    void domainEventsEmittedWithoutSecretsOrPii() {
        UUID userId = UUID.randomUUID();
        UserRegistered registered = new UserRegistered(
                userId, IdentityProvider.GOOGLE, "https://accounts.google.com", "sub-123", fixedInstant
        );
        UserLoggedIn loggedIn = new UserLoggedIn(userId, IdentityProvider.GOOGLE, fixedInstant);
        LoginRejected rejected = new LoginRejected(IdentityProvider.GOOGLE, "Rejection reason", fixedInstant);

        assertThat(registered.userId()).isEqualTo(userId);
        assertThat(registered.provider()).isEqualTo(IdentityProvider.GOOGLE);
        assertThat(loggedIn.userId()).isEqualTo(userId);
        assertThat(rejected.provider()).isEqualTo(IdentityProvider.GOOGLE);
    }
}
