package com.burnbox.identity;

import com.burnbox.platform.SecurityEventPublisher;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Service orchestrating OIDC federated user provisioning according to Section 6.
 * Enforces (issuer, sub) identity invariant (BR-001), nOAuth anti-account-takeover
 * mitigation (BR-002), and strict user status checks (BR-003).
 */
@Service
public class UserProvisioningService {

    private final UserRepository userRepository;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final SecurityEventPublisher securityEventPublisher;
    private final Clock clock;

    public UserProvisioningService(
            UserRepository userRepository,
            ApplicationEventPublisher applicationEventPublisher,
            SecurityEventPublisher securityEventPublisher,
            Clock clock
    ) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.applicationEventPublisher = Objects.requireNonNull(applicationEventPublisher, "applicationEventPublisher must not be null");
        this.securityEventPublisher = Objects.requireNonNull(securityEventPublisher, "securityEventPublisher must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Transactional
    public ProvisioningResult authenticateOrProvision(OidcIdentityClaims claims) {
        Objects.requireNonNull(claims, "claims must not be null");
        Instant now = Instant.now(clock);

        // 1. Check if (issuer, sub) already exists
        Optional<LinkedIdentity> existingIdentity = userRepository.findIdentity(claims.issuer(), claims.subject());

        if (existingIdentity.isPresent()) {
            LinkedIdentity identity = existingIdentity.get();
            AppUser user = userRepository.findById(identity.userId())
                    .orElseThrow(() -> new IllegalStateException("User missing for identity " + identity.id()));

            // BR-003: Check user status
            if (user.status() == UserStatus.DISABLED) {
                applicationEventPublisher.publishEvent(new LoginRejected(
                        claims.provider(), "User account is disabled", now
                ));
                securityEventPublisher.publish("LOGIN_REJECTED", "user", user.id().toString(), Map.of(
                        "provider", claims.provider().name(),
                        "reason", "ACCOUNT_DISABLED"
                ));
                return new ProvisioningResult.RejectedDisabled("La cuenta de usuario está inhabilitada.");
            }

            // Update timestamps
            userRepository.updateLastLogin(user.id(), now);
            userRepository.updateIdentityLastUsed(identity.id(), now);

            applicationEventPublisher.publishEvent(new UserLoggedIn(user.id(), claims.provider(), now));
            securityEventPublisher.publish("USER_LOGGED_IN", "user", user.id().toString(), Map.of(
                    "provider", claims.provider().name()
            ));

            boolean warning = (user.status() == UserStatus.PENDING_DELETION);
            return new ProvisioningResult.Success(user, false, warning);
        }

        // 2. nOAuth Prevention: If identity is new, check if verified email collides with an existing verified account
        if (claims.emailVerified() && claims.email() != null && !claims.email().isBlank()) {
            Optional<AppUser> existingEmailUser = userRepository.findByVerifiedEmail(claims.email());
            if (existingEmailUser.isPresent()) {
                // Reject auto-merge!
                applicationEventPublisher.publishEvent(new LoginRejected(
                        claims.provider(), "Email collision with existing verified account (nOAuth protection)", now
                ));
                securityEventPublisher.publish("LOGIN_REJECTED", "identity", claims.subject(), Map.of(
                        "provider", claims.provider().name(),
                        "reason", "NOAUTH_COLLISION"
                ));
                return new ProvisioningResult.CollisionBlocked(claims.email(), "original_provider");
            }
        }

        // 3. Provision new User and Identity
        UUID newUserId = UUID.randomUUID();
        AppUser newUser = new AppUser(
                newUserId,
                claims.displayName(),
                claims.email(),
                claims.emailVerified(),
                UserStatus.ACTIVE,
                null,
                claims.locale() != null ? claims.locale() : "es",
                now,
                now
        );
        userRepository.insertUser(newUser);

        UUID identityId = UUID.randomUUID();
        LinkedIdentity newIdentity = new LinkedIdentity(
                identityId,
                newUserId,
                claims.provider(),
                claims.issuer(),
                claims.subject(),
                claims.email(),
                claims.emailVerified(),
                now,
                now
        );
        userRepository.insertIdentity(newIdentity);

        applicationEventPublisher.publishEvent(new UserRegistered(
                newUserId, claims.provider(), claims.issuer(), claims.subject(), now
        ));
        applicationEventPublisher.publishEvent(new UserLoggedIn(newUserId, claims.provider(), now));

        securityEventPublisher.publish("USER_REGISTERED", "user", newUserId.toString(), Map.of(
                "provider", claims.provider().name()
        ));
        securityEventPublisher.publish("USER_LOGGED_IN", "user", newUserId.toString(), Map.of(
                "provider", claims.provider().name()
        ));

        return new ProvisioningResult.Success(newUser, true, false);
    }
}
