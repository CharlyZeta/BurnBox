package com.burnbox.secret;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Controller for creating secrets via server-side rendered forms.
 * Enforces payload limits (64 KiB, BR-001), TTL options (BR-002),
 * and view limits (BR-003).
 */
@Controller
public class SecretWebController {

    public static final int MAX_CONTENT_BYTES = 65536; // 64 KiB
    private static final Set<String> ALLOWED_TTLS = Set.of("5m", "1h", "1d", "7d");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private final SecretService secretService;

    public SecretWebController(SecretService secretService) {
        this.secretService = secretService;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("form", new CreateSecretForm("", "1h", 1));
        return "index";
    }

    @PostMapping("/secrets")
    public String createSecret(
            @ModelAttribute("form") CreateSecretForm form,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        String content = form.content();

        if (content == null || content.trim().isEmpty()) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            model.addAttribute("error", "El contenido del secreto no puede estar vacío");
            model.addAttribute("form", form);
            return "index";
        }

        byte[] plaintext = content.getBytes(StandardCharsets.UTF_8);
        if (plaintext.length > MAX_CONTENT_BYTES) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            model.addAttribute("error", "El tamaño del secreto excede el límite permitido de 64 KiB");
            model.addAttribute("form", form);
            return "index";
        }

        String ttlStr = form.ttl() != null ? form.ttl().trim().toLowerCase() : "1h";
        if (!ALLOWED_TTLS.contains(ttlStr)) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            model.addAttribute("error", "Opción de expiración (TTL) no permitida");
            model.addAttribute("form", form);
            return "index";
        }

        Integer maxViews = form.maxViews();
        if (maxViews == null || maxViews < 1 || maxViews > 10) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            model.addAttribute("error", "El límite de visualizaciones debe estar comprendido entre 1 y 10");
            model.addAttribute("form", form);
            return "index";
        }

        Duration ttl = form.parseTtl();
        UUID ownerUserId = resolveOwnerUserId();

        String passphrase = (form.passphrase() != null && !form.passphrase().isBlank())
                ? form.passphrase().trim()
                : null;

        if (passphrase != null && (passphrase.length() < 8 || passphrase.length() > 128)) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            model.addAttribute("error", "La contraseña debe tener entre 8 y 128 caracteres");
            model.addAttribute("form", form);
            return "index";
        }

        String recipientEmail = (form.recipientEmail() != null && !form.recipientEmail().isBlank())
                ? form.recipientEmail().trim().toLowerCase()
                : null;

        if (recipientEmail != null && !EMAIL_PATTERN.matcher(recipientEmail).matches()) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            model.addAttribute("error", "El formato del email de destinatario es inválido");
            model.addAttribute("form", form);
            return "index";
        }

        CreateSecretCommand cmd = new CreateSecretCommand(
                plaintext,
                ttl,
                maxViews,
                ownerUserId,
                recipientEmail,
                null,
                passphrase
        );

        CreateSecretResult result = secretService.createSecret(cmd);

        // Cabeceras estrictas de anti-almacenamiento y anti-indexación (BR-006 / AC-007)
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Robots-Tag", "noindex, nofollow");

        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String portPart = (("http".equals(scheme) && serverPort == 80) || ("https".equals(scheme) && serverPort == 443))
                ? ""
                : ":" + serverPort;
        String secretUrl = scheme + "://" + serverName + portPart + "/s/" + result.rawToken();

        model.addAttribute("secretUrl", secretUrl);
        model.addAttribute("rawToken", result.rawToken());
        model.addAttribute("expiresAt", result.expiresAt());
        model.addAttribute("maxViews", maxViews);

        return "secret-created";
    }

    private UUID resolveOwnerUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            try {
                return UUID.fromString(auth.getName());
            } catch (IllegalArgumentException ignored) {
                return null;
            }
        }
        return null;
    }
}
