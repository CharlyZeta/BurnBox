package com.burnbox.identity;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class BurnboxOidcUserService extends OidcUserService {

    private final UserProvisioningService provisioningService;

    public BurnboxOidcUserService(UserProvisioningService provisioningService) {
        this.provisioningService = Objects.requireNonNull(provisioningService, "provisioningService must not be null");
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        return processOidcUser(userRequest.getClientRegistration().getRegistrationId(), oidcUser);
    }

    public BurnboxOidcUser processOidcUser(String registrationId, OidcUser oidcUser) throws OAuth2AuthenticationException {
        IdentityProvider provider = IdentityProvider.fromRegistrationId(registrationId);

        String issuer;
        if (oidcUser.getIssuer() != null) {
            issuer = oidcUser.getIssuer().toString();
        } else if (provider == IdentityProvider.MICROSOFT) {
            String tid = oidcUser.getClaimAsString("tid");
            issuer = tid != null ? "https://login.microsoftonline.com/" + tid + "/v2.0" : "https://login.microsoftonline.com/common/v2.0";
        } else {
            issuer = "https://accounts.google.com";
        }

        String subject = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        if (email == null || email.isBlank()) {
            email = oidcUser.getPreferredUsername();
        }

        // BR-002: Strict email_verified invariant. If missing or false, cannot be treated as verified email
        boolean emailVerified = Boolean.TRUE.equals(oidcUser.getEmailVerified());

        String displayName = oidcUser.getFullName();
        if (displayName == null || displayName.isBlank()) {
            displayName = oidcUser.getPreferredUsername();
        }
        String locale = oidcUser.getLocale();

        OidcIdentityClaims claims = new OidcIdentityClaims(
                provider,
                issuer,
                subject,
                email,
                emailVerified,
                displayName,
                locale
        );

        ProvisioningResult result = provisioningService.authenticateOrProvision(claims);

        return switch (result) {
            case ProvisioningResult.Success success -> new BurnboxOidcUser(oidcUser, success.user());
            case ProvisioningResult.RejectedDisabled disabled -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("account_disabled", disabled.reason(), null)
            );
            case ProvisioningResult.CollisionBlocked collision -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_collision", "Email already registered with another provider. Please log in with original provider.", "/login?error=collision")
            );
        };
    }
}
