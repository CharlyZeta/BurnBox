package com.burnbox.secret;

import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.ratelimit.AbuseDetector;
import com.burnbox.ratelimit.ClientIpExtractor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Controller for anonymous SSR secret revealing.
 * Enforces GET intermediate page (crawlers protection, BR-001),
 * POST-only consumption (BR-002), anonymous double-submit CSRF (BR-003),
 * anti-cache / anti-index headers (BR-006), and uniform unavailable responses (BR-005).
 */
@Controller
@RequestMapping("/s")
public class RevealController {

    public static final String CSRF_COOKIE_NAME = "burnbox_reveal_csrf";
    private static final Pattern TOKEN_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{43}$");

    private final SecretService secretService;
    private final CryptoTokenService tokenService;
    private final AbuseDetector abuseDetector;
    private final ClientIpExtractor ipExtractor;

    public RevealController(
            SecretService secretService,
            CryptoTokenService tokenService,
            ObjectProvider<AbuseDetector> abuseDetectorProvider,
            ObjectProvider<ClientIpExtractor> ipExtractorProvider
    ) {
        this.secretService = secretService;
        this.tokenService = tokenService;
        this.abuseDetector = abuseDetectorProvider.getIfAvailable();
        this.ipExtractor = ipExtractorProvider.getIfAvailable();
    }

    @GetMapping("/{token}")
    public String showIntermediate(
            @PathVariable("token") String token,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        addAntiCacheAndRobotsHeaders(response);

        if (!isValidToken(token)) {
            return "reveal-unavailable";
        }

        String csrfToken = tokenService.generateToken();

        ResponseCookie cookie = ResponseCookie.from(CSRF_COOKIE_NAME, csrfToken)
                .path("/s/")
                .sameSite("Strict")
                .httpOnly(true)
                .secure(request.isSecure())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        model.addAttribute("token", token);
        model.addAttribute("csrfToken", csrfToken);

        return "reveal-intermediate";
    }

    @PostMapping("/{token}/reveal")
    public String revealSecret(
            @PathVariable("token") String token,
            @RequestParam(value = "_csrf", required = false) String formCsrf,
            @CookieValue(value = CSRF_COOKIE_NAME, required = false) String cookieCsrf,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        addAntiCacheAndRobotsHeaders(response);

        // BR-003 / AC-004: Validación estricta de CSRF por doble envío anónimo
        if (cookieCsrf == null || formCsrf == null || !cookieCsrf.equals(formCsrf)) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return "error";
        }

        if (!isValidToken(token)) {
            recordFailureIfPossible(request, token);
            return "reveal-unavailable";
        }

        String tokenHash = tokenService.hashToken(token);
        SecretAccessResult result = secretService.consumeSecret(tokenHash);

        // BR-007 / AC-008: Pattern matching exhaustivo sobre sealed interface SecretAccessResult
        return switch (result) {
            case SecretAccessResult.Success success -> {
                model.addAttribute("content", new String(success.plaintext(), StandardCharsets.UTF_8));
                model.addAttribute("views", success.views());
                model.addAttribute("maxViews", success.maxViews());
                model.addAttribute("state", success.state());
                yield "reveal-content";
            }
            case SecretAccessResult.NotAvailable notAvailable -> {
                recordFailureIfPossible(request, tokenHash);
                // BR-005 / AC-005: Respuesta uniforme indistinguible para cualquier motivo de no disponibilidad
                yield "reveal-unavailable";
            }
        };
    }

    private void recordFailureIfPossible(HttpServletRequest request, String tokenIdentifier) {
        if (abuseDetector != null && ipExtractor != null && request != null) {
            String clientIp = ipExtractor.extractClientIp(request);
            String prefix = ipExtractor.normalizeToPrefix(clientIp);
            abuseDetector.recordFailedTokenAttempt(prefix, tokenIdentifier);
        }
    }

    private void addAntiCacheAndRobotsHeaders(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Robots-Tag", "noindex, nofollow");
    }

    private boolean isValidToken(String token) {
        return token != null && TOKEN_PATTERN.matcher(token.trim()).matches();
    }
}
