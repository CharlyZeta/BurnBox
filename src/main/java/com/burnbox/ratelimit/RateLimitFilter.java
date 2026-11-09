package com.burnbox.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enforces rate limiting and abuse defense across sensitive endpoints:
 * - POST /secrets: CREATE_IP (30 req/h)
 * - /s/**: REVEAL_IP (20 req/min) and REVEAL_TOKEN (10 req/min)
 * - Temporary abuse blocks (1 hour)
 * Returns uniform HTTP 429 with Retry-After header and no leakage of internal bucket metadata.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Pattern SECRET_URL_PATTERN = Pattern.compile("^/s/([A-Za-z0-9_-]{20,64})(?:/.*)?$");

    private final RateLimiter rateLimiter;
    private final AbuseDetector abuseDetector;
    private final ClientIpExtractor ipExtractor;

    public RateLimitFilter(
            org.springframework.beans.factory.ObjectProvider<RateLimiter> rateLimiterProvider,
            org.springframework.beans.factory.ObjectProvider<AbuseDetector> abuseDetectorProvider,
            org.springframework.beans.factory.ObjectProvider<ClientIpExtractor> ipExtractorProvider
    ) {
        this.rateLimiter = rateLimiterProvider.getIfAvailable();
        this.abuseDetector = abuseDetectorProvider.getIfAvailable();
        this.ipExtractor = ipExtractorProvider.getIfAvailable();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (rateLimiter == null || ipExtractor == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        String method = request.getMethod();

        String clientIp = ipExtractor.extractClientIp(request);
        String ipPrefix = ipExtractor.normalizeToPrefix(clientIp);

        // 1. Check if IP prefix is blocked for abuse
        if (abuseDetector != null && abuseDetector.isBlocked(ipPrefix)) {
            long remaining = abuseDetector.getBlockRemainingSeconds(ipPrefix);
            send429Response(response, remaining);
            return;
        }

        // 2. Secret creation: POST /secrets
        if ("POST".equalsIgnoreCase(method) && "/secrets".equals(path)) {
            RateLimitResult result = rateLimiter.tryConsume(ipPrefix, BucketType.CREATE_IP);
            if (result instanceof RateLimitResult.Denied denied) {
                send429Response(response, denied.retryAfterSeconds());
                return;
            }
        }

        // 3. Secret reveal endpoints: /s/**
        if (path.startsWith("/s/")) {
            // Check IP rate limit (reveal-ip)
            RateLimitResult ipResult = rateLimiter.tryConsume(ipPrefix, BucketType.REVEAL_IP);
            if (ipResult instanceof RateLimitResult.Denied denied) {
                send429Response(response, denied.retryAfterSeconds());
                return;
            }

            // Check token-specific rate limit (reveal-token)
            Matcher matcher = SECRET_URL_PATTERN.matcher(path);
            if (matcher.matches()) {
                String token = matcher.group(1);
                String tokenHash = hashToken(token);
                RateLimitResult tokenResult = rateLimiter.tryConsume(tokenHash, BucketType.REVEAL_TOKEN);
                if (tokenResult instanceof RateLimitResult.Denied denied) {
                    send429Response(response, denied.retryAfterSeconds());
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private void send429Response(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(Math.max(1, retryAfterSeconds)));
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("""
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <title>429 - Límite de peticiones excedido</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0b0f19; color: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; max-width: 480px; text-align: center; }
                        h1 { color: #f87171; font-size: 1.5rem; margin-bottom: 1rem; }
                        p { color: #94a3b8; font-size: 0.95rem; line-height: 1.5; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <h1>Demasiadas peticiones</h1>
                        <p>Ha superado el límite de operaciones permitidas. Por favor, reintente nuevamente más tarde.</p>
                    </div>
                </body>
                </html>
                """);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
