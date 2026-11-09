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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Controller for anonymous SSR secret revealing.
 * Enforces GET intermediate page (crawlers protection, BR-001),
 * POST-only consumption (BR-002), anonymous double-submit CSRF (BR-003),
 * anti-cache / anti-index headers (BR-006), uniform unavailable responses (BR-005),
 * and restricted recipient validation (FEAT-0014).
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
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        addAntiCacheAndRobotsHeaders(response);

        if (!isValidToken(token)) {
            return "reveal-unavailable";
        }

        String tokenHash = tokenService.hashToken(token);
        CallerInfo caller = extractCallerInfo(authentication);
        SecretAccessResult checkResult = secretService.checkAccess(tokenHash, caller.email(), caller.verified());

        if (checkResult instanceof SecretAccessResult.RecipientLoginRequired) {
            model.addAttribute("token", token);
            return "reveal-login-required";
        }
        if (checkResult instanceof SecretAccessResult.NotAvailable) {
            recordFailureIfPossible(request, tokenHash);
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
            @RequestParam(value = "passphrase", required = false) String passphrase,
            @CookieValue(value = CSRF_COOKIE_NAME, required = false) String cookieCsrf,
            Authentication authentication,
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
        CallerInfo caller = extractCallerInfo(authentication);

        SecretAccessResult result;
        if (caller.email() != null || caller.verified()) {
            result = secretService.consumeSecret(
                    tokenHash,
                    (passphrase != null && !passphrase.isBlank()) ? passphrase.trim() : null,
                    caller.email(),
                    caller.verified()
            );
        } else if (passphrase != null && !passphrase.isBlank()) {
            result = secretService.consumeSecret(tokenHash, passphrase.trim());
        } else {
            result = secretService.consumeSecret(tokenHash);
        }

        if (result == null) {
            result = new SecretAccessResult.NotAvailable("Internal error");
        }

        // BR-007 / AC-008: Pattern matching exhaustivo sobre sealed interface SecretAccessResult
        return switch (result) {
            case SecretAccessResult.Success success -> {
                model.addAttribute("content", new String(success.plaintext(), StandardCharsets.UTF_8));
                model.addAttribute("views", success.views());
                model.addAttribute("maxViews", success.maxViews());
                model.addAttribute("state", success.state());
                yield "reveal-content";
            }
            case SecretAccessResult.PassphraseRequired passphraseRequired -> {
                model.addAttribute("token", token);
                model.addAttribute("csrfToken", cookieCsrf);
                yield "reveal-passphrase";
            }
            case SecretAccessResult.WrongPassphrase wrong -> {
                model.addAttribute("token", token);
                model.addAttribute("csrfToken", cookieCsrf);
                model.addAttribute("remainingAttempts", wrong.remainingAttempts());
                model.addAttribute("error", "Contraseña incorrecta. Le quedan " + wrong.remainingAttempts() + " intento(s) antes de su destrucción.");
                yield "reveal-passphrase";
            }
            case SecretAccessResult.RecipientLoginRequired loginRequired -> {
                model.addAttribute("token", token);
                yield "reveal-login-required";
            }
            case SecretAccessResult.NotAvailable notAvailable -> {
                recordFailureIfPossible(request, tokenHash);
                // BR-005 / AC-005: Respuesta uniforme indistinguible para cualquier motivo de no disponibilidad
                yield "reveal-unavailable";
            }
        };
    }

    private record CallerInfo(String email, boolean verified) {}

    private CallerInfo extractCallerInfo(Authentication auth) {
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return new CallerInfo(null, false);
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            String email = oidcUser.getEmail();
            Boolean ev = oidcUser.getEmailVerified();
            if (ev == null) {
                Object claim = oidcUser.getClaims().get("email_verified");
                if (claim instanceof Boolean b) ev = b;
                else if (claim instanceof String s) ev = Boolean.parseBoolean(s);
            }
            return new CallerInfo(email, Boolean.TRUE.equals(ev));
        } else if (principal instanceof OAuth2User oauth2User) {
            String email = oauth2User.getAttribute("email");
            Boolean ev = oauth2User.getAttribute("email_verified");
            return new CallerInfo(email, Boolean.TRUE.equals(ev));
        } else if (principal instanceof UserDetails userDetails) {
            String username = userDetails.getUsername();
            if (username != null && username.contains("@")) {
                return new CallerInfo(username, true);
            }
        }

        if (auth.getName() != null && auth.getName().contains("@")) {
            return new CallerInfo(auth.getName(), true);
        }

        return new CallerInfo(null, false);
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
