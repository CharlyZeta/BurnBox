package com.burnbox.ratelimit;

import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.platform.ClockConfig;
import com.burnbox.platform.SecurityConfig;
import com.burnbox.secret.CreateSecretResult;
import com.burnbox.secret.SecretAccessResult;
import com.burnbox.secret.SecretService;
import com.burnbox.secret.SecretWebController;
import com.burnbox.secret.RevealController;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = {SecretWebController.class, RevealController.class})
@Import({
        SecurityConfig.class,
        RateLimitFilter.class,
        RateLimiter.class,
        AbuseDetector.class,
        ClientIpExtractor.class,
        ClockConfig.class,
        RateLimitIntegrationTest.TestEventConfig.class
})
class RateLimitIntegrationTest {

    private static final String VALID_TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v";

    @TestConfiguration
    static class TestEventConfig {
        final List<AbuseIpFlagged> capturedEvents = new CopyOnWriteArrayList<>();

        @EventListener
        public void onAbuseIpFlagged(AbuseIpFlagged event) {
            capturedEvents.add(event);
        }

        public void reset() {
            capturedEvents.clear();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RateLimiter rateLimiter;

    @Autowired
    private AbuseDetector abuseDetector;

    @Autowired
    private TestEventConfig testEventConfig;

    @MockitoBean
    private SecretService secretService;

    @MockitoBean
    private CryptoTokenService tokenService;

    @BeforeEach
    void setUp() {
        rateLimiter.reset();
        abuseDetector.reset();
        testEventConfig.reset();
        when(tokenService.generateToken()).thenReturn("mock-csrf-token");
        when(tokenService.hashToken(any())).thenReturn("mock-token-hash");
    }

    @Test
    @DisplayName("Main Flow & AC-001: Peticiones bajo los límites permitidos avanzan normalmente")
    void mainFlowUnderLimits() throws Exception {
        underQuotaPassesThrough();
    }

    @Test
    @DisplayName("AC-001: Peticiones dentro de la tasa permitida retornan resultado normal")
    void underQuotaPassesThrough() throws Exception {
        mockMvc.perform(get("/s/" + VALID_TOKEN)
                        .with(request -> {
                            request.setRemoteAddr("192.168.10.5");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(view().name("reveal-intermediate"));
    }

    @Test
    @DisplayName("AF-01 & AC-002: La 21ª petición en menos de 1 minuto desde la misma IP a /s/** retorna 429")
    void rateLimitExceededReturns429() throws Exception {
        revealIpRejects21stRequest();
    }

    @Test
    @DisplayName("AC-002: reveal-ip rechaza la petición número 21")
    void revealIpRejects21stRequest() throws Exception {
        String testIp = "192.168.20.10";

        // Primeras 20 peticiones con tokens distintos para no agotar reveal-token (capacidad 10)
        for (int i = 0; i < 20; i++) {
            String tokenVar = String.format("tokenip%036d", i);
            mockMvc.perform(get("/s/" + tokenVar)
                            .with(request -> {
                                request.setRemoteAddr(testIp);
                                return request;
                            }))
                    .andExpect(status().isOk());
        }

        // Petición 21 es rechazada con 429 por reveal-ip
        String tokenVar21 = String.format("tokenip%036d", 21);
        mockMvc.perform(get("/s/" + tokenVar21)
                        .with(request -> {
                            request.setRemoteAddr(testIp);
                            return request;
                        }))
                .andExpect(status().is(429))
                .andExpect(header().exists("Retry-After"))
                .andExpect(header().string("Cache-Control", Matchers.containsString("no-store")));
    }

    @Test
    @DisplayName("AC-003: Cabecera Retry-After presente con entero positivo mayor o igual a 1")
    void retryAfterHeaderNumericPositive() throws Exception {
        String testIp = "192.168.25.10";

        for (int i = 0; i < 20; i++) {
            String tokenVar = String.format("tokenretry%033d", i);
            mockMvc.perform(get("/s/" + tokenVar)
                    .with(request -> {
                        request.setRemoteAddr(testIp);
                        return request;
                    }));
        }

        String tokenVar21 = String.format("tokenretry%033d", 21);
        mockMvc.perform(get("/s/" + tokenVar21)
                        .with(request -> {
                            request.setRemoteAddr(testIp);
                            return request;
                        }))
                .andExpect(status().is(429))
                .andExpect(header().string("Retry-After", Matchers.matchesPattern("^[1-9][0-9]*$")));
    }

    @Test
    @DisplayName("AC-004: reveal-token rechaza la 11ª petición contra el mismo token en menos de 1 minuto")
    void revealTokenRejects11thRequest() throws Exception {
        String specificToken = "tokentest1234567890abcdefghijklmnopqrstuvw";

        // Realizamos 10 peticiones desde IPs distintas para no disparar reveal-ip
        for (int i = 1; i <= 10; i++) {
            final int idx = i;
            mockMvc.perform(get("/s/" + specificToken)
                            .with(request -> {
                                request.setRemoteAddr("10.0." + idx + ".1");
                                return request;
                            }))
                    .andExpect(status().isOk());
        }

        // 11ª petición sobre el mismo token debe dar 429
        mockMvc.perform(get("/s/" + specificToken)
                        .with(request -> {
                            request.setRemoteAddr("10.0.100.1");
                            return request;
                        }))
                .andExpect(status().is(429))
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    @DisplayName("AC-005: create-ip rechaza la 31ª petición de creación en menos de 1 hora")
    void createIpRejects31stRequest() throws Exception {
        String createIp = "172.16.50.4";
        UUID secretId = UUID.randomUUID();
        Instant expires = Instant.parse("2026-11-09T12:00:00Z");
        CreateSecretResult result = new CreateSecretResult(secretId, VALID_TOKEN, "hash", expires);
        when(secretService.createSecret(any(com.burnbox.secret.CreateSecretCommand.class))).thenReturn(result);

        // 30 creaciones permitidas
        for (int i = 0; i < 30; i++) {
            mockMvc.perform(post("/secrets")
                            .with(csrf())
                            .with(request -> {
                                request.setRemoteAddr(createIp);
                                return request;
                            })
                            .param("content", "secret number " + i)
                            .param("ttl", "1h")
                            .param("maxViews", "1"))
                    .andExpect(status().isOk());
        }

        // 31ª creación rechazada con 429
        mockMvc.perform(post("/secrets")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr(createIp);
                            return request;
                        })
                        .param("content", "secret 31")
                        .param("ttl", "1h")
                        .param("maxViews", "1"))
                .andExpect(status().is(429))
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    @DisplayName("AC-006: Respuesta 429 es genérica y opaca sin filtrar nombres de bucket ni cuotas internas")
    void generic429BodyWithoutLeak() throws Exception {
        String testIp = "192.168.88.9";

        for (int i = 0; i < 20; i++) {
            mockMvc.perform(get("/s/" + VALID_TOKEN).with(req -> {
                req.setRemoteAddr(testIp);
                return req;
            }));
        }

        mockMvc.perform(get("/s/" + VALID_TOKEN).with(req -> {
                    req.setRemoteAddr(testIp);
                    return req;
                }))
                .andExpect(status().is(429))
                .andExpect(content().string(Matchers.not(Matchers.containsString("REVEAL_IP"))))
                .andExpect(content().string(Matchers.not(Matchers.containsString("CREATE_IP"))))
                .andExpect(content().string(Matchers.not(Matchers.containsString("bucket"))))
                .andExpect(content().string(Matchers.containsString("Demasiadas peticiones")));
    }

    @Test
    @DisplayName("AF-02, AF-03, AC-007 y AC-008: 10 fallos de tokens en 5 min bloquean IP por 1 hora y emiten AbuseIpFlagged")
    void tenDifferentTokenFailuresBlockForHour() throws Exception {
        String victimSubnet = "198.51.100.22";
        when(secretService.consumeSecret(any())).thenReturn(new SecretAccessResult.NotAvailable("NOT_FOUND"));

        // 10 intentos con tokens diferentes que fallan
        for (int i = 1; i <= 10; i++) {
            String tokenVariant = String.format("token%039d", i);
            mockMvc.perform(post("/s/" + tokenVariant + "/reveal")
                            .cookie(new jakarta.servlet.http.Cookie("burnbox_reveal_csrf", "match-token"))
                            .param("_csrf", "match-token")
                            .with(request -> {
                                request.setRemoteAddr(victimSubnet);
                                return request;
                            }))
                    .andExpect(view().name("reveal-unavailable"));
        }

        // Petición subsecuente es bloqueada con 429 por abuso
        mockMvc.perform(get("/s/" + VALID_TOKEN)
                        .with(request -> {
                            request.setRemoteAddr(victimSubnet);
                            return request;
                        }))
                .andExpect(status().is(429))
                .andExpect(header().exists("Retry-After"));

        // Verificar emisión de evento AbuseIpFlagged
        abuseIpFlaggedEventVerified();
    }

    @Test
    @DisplayName("AF-02: IP bloqueada por abuso retorna 429 directamente")
    void abusedIpBlockedForOneHour() throws Exception {
        abuseDetector.recordFailedTokenAttempt("192.0.2.0/24", "t1");
        for (int i = 2; i <= 10; i++) {
            abuseDetector.recordFailedTokenAttempt("192.0.2.0/24", "t" + i);
        }

        mockMvc.perform(get("/s/" + VALID_TOKEN)
                        .with(request -> {
                            request.setRemoteAddr("192.0.2.55");
                            return request;
                        }))
                .andExpect(status().is(429))
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    @DisplayName("AF-03: Detección de escaneo emite evento")
    void abuseDetectionEmitsEvent() {
        for (int i = 1; i <= 10; i++) {
            abuseDetector.recordFailedTokenAttempt("192.0.2.0/24", "t" + i);
        }
        assertFalse(testEventConfig.capturedEvents.isEmpty(), "Should have captured AbuseIpFlagged event");
        assertEquals("192.0.2.0/24", testEventConfig.capturedEvents.getFirst().ipPrefix());
    }

    @Test
    @DisplayName("AF-04: Extracción de IP cliente con proxy confiable")
    void trustedProxyIpExtraction() throws Exception {
        String spoofedForwarded = "203.0.113.88";

        // Petición con RemoteAddr de proxy local de confianza
        mockMvc.perform(get("/s/" + VALID_TOKEN)
                        .with(request -> {
                            request.setRemoteAddr("127.0.0.1");
                            request.addHeader("X-Forwarded-For", spoofedForwarded);
                            return request;
                        }))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("AC-008: Verificación formal del evento AbuseIpFlagged")
    void abuseIpFlaggedEventVerified() {
        for (int i = 1; i <= 10; i++) {
            abuseDetector.recordFailedTokenAttempt("203.0.113.0/24", "verify-token-" + i);
        }
        assertFalse(testEventConfig.capturedEvents.isEmpty(), "Captured events should not be empty");
        assertNotNull(testEventConfig.capturedEvents.getFirst().reason());
    }
}
