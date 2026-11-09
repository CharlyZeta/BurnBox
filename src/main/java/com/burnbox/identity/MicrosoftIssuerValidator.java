package com.burnbox.identity;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URL;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates Microsoft Entra ID multi-tenant issuers (BR-001).
 * Expects issuer matching: https://login.microsoftonline.com/{tid}/v2.0
 * and verifies that the tenant ID matches the 'tid' claim present in the token.
 */
public class MicrosoftIssuerValidator implements OAuth2TokenValidator<Jwt> {

    private static final Pattern ISSUER_PATTERN = Pattern.compile(
            "^https://login\\.microsoftonline\\.com/([a-fA-F0-9\\-]{36})/v2\\.0$"
    );

    private static final OAuth2Error INVALID_ISSUER_FORMAT = new OAuth2Error(
            "invalid_issuer",
            "The issuer does not match the Microsoft Entra ID tenant issuer pattern https://login.microsoftonline.com/{tid}/v2.0",
            null
    );

    private static final OAuth2Error TID_MISMATCH = new OAuth2Error(
            "invalid_issuer",
            "The issuer tenant ID does not match the 'tid' claim in the token",
            null
    );

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        Objects.requireNonNull(token, "token must not be null");

        URL issuer = token.getIssuer();
        if (issuer == null) {
            return OAuth2TokenValidatorResult.failure(INVALID_ISSUER_FORMAT);
        }

        String issuerStr = issuer.toString();
        Matcher matcher = ISSUER_PATTERN.matcher(issuerStr);
        if (!matcher.matches()) {
            return OAuth2TokenValidatorResult.failure(INVALID_ISSUER_FORMAT);
        }

        String issuerTid = matcher.group(1);
        String tokenTid = token.getClaimAsString("tid");

        if (tokenTid == null || !issuerTid.equalsIgnoreCase(tokenTid)) {
            return OAuth2TokenValidatorResult.failure(TID_MISMATCH);
        }

        return OAuth2TokenValidatorResult.success();
    }
}
