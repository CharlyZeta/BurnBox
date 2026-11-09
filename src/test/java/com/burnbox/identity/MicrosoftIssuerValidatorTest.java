package com.burnbox.identity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MicrosoftIssuerValidatorTest {

    private MicrosoftIssuerValidator validator;
    private final Instant fixedTime = Instant.parse("2026-11-09T16:00:00Z");

    @BeforeEach
    void setUp() {
        validator = new MicrosoftIssuerValidator();
    }

    private Jwt createMockJwt(String issuerStr, String tid) {
        Jwt.Builder builder = Jwt.withTokenValue("mock-jwt-token")
                .header("alg", "RS256")
                .issuedAt(fixedTime)
                .expiresAt(fixedTime.plusSeconds(3600))
                .subject("ms-user-sub-12345");

        if (issuerStr != null) {
            builder.issuer(issuerStr);
        }
        if (tid != null) {
            builder.claim("tid", tid);
        }
        return builder.build();
    }

    @Test
    @DisplayName("AC-001 / BR-001: Token con issuer válido y tid coincidente supera la validación")
    void validTenantIssuerMatchesTid() {
        String tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";

        Jwt jwt = createMockJwt(issuer, tid);

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("AC-002 / AF-01: Issuer con formato no correspondiente a Microsoft Entra ID falla")
    void invalidIssuerFormatFails() {
        Jwt jwt1 = createMockJwt("https://malicious-issuer.com/tenant/v2.0", "72f988bf-86f1-41af-91ab-2d7cd011db47");
        OAuth2TokenValidatorResult result1 = validator.validate(jwt1);
        assertThat(result1.hasErrors()).isTrue();
        assertThat(result1.getErrors()).anyMatch(err -> err.getErrorCode().equals("invalid_issuer"));

        Jwt jwt2 = createMockJwt("https://login.microsoftonline.com/common/v2.0", "72f988bf-86f1-41af-91ab-2d7cd011db47");
        OAuth2TokenValidatorResult result2 = validator.validate(jwt2);
        assertThat(result2.hasErrors()).isTrue();

        Jwt jwt3 = createMockJwt(null, "72f988bf-86f1-41af-91ab-2d7cd011db47");
        OAuth2TokenValidatorResult result3 = validator.validate(jwt3);
        assertThat(result3.hasErrors()).isTrue();
    }

    @Test
    @DisplayName("AC-002 / BR-001: Issuer cuyo tid no coincide con el claim tid del token falla")
    void tidMismatchFails() {
        String issuerTid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        String claimTid = "00000000-0000-0000-0000-000000000000";
        String issuer = "https://login.microsoftonline.com/" + issuerTid + "/v2.0";

        Jwt jwt = createMockJwt(issuer, claimTid);

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(err -> err.getDescription().contains("does not match the 'tid' claim"));
    }

    @Test
    @DisplayName("AC-002: Token que carece del claim tid falla")
    void missingTidClaimFails() {
        String issuerTid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        String issuer = "https://login.microsoftonline.com/" + issuerTid + "/v2.0";

        Jwt jwt = createMockJwt(issuer, null);

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
    }
}
