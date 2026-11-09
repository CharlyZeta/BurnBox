package com.burnbox.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.Set;

/**
 * Extracts and normalizes client IP addresses for rate limiting and abuse detection.
 * Enforces /24 subnet grouping for IPv4 and /64 for IPv6 to prevent circumventing
 * rate limits through neighboring IPs.
 * Proxy headers (X-Forwarded-For) are only honored if remote address matches a trusted proxy.
 */
@Component
public class ClientIpExtractor {

    private final Set<String> trustedProxies;

    public ClientIpExtractor() {
        this(Set.of("127.0.0.1", "0:0:0:0:0:0:0:1", "::1"));
    }

    public ClientIpExtractor(Set<String> trustedProxies) {
        this.trustedProxies = trustedProxies != null ? trustedProxies : Set.of();
    }

    public String extractClientIp(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr == null || remoteAddr.isBlank()) {
            return "0.0.0.0";
        }

        if (isTrustedProxy(remoteAddr)) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                // First element in X-Forwarded-For is client
                String[] parts = forwarded.split(",");
                if (parts.length > 0) {
                    String clientCandidate = parts[0].trim();
                    if (!clientCandidate.isBlank()) {
                        return clientCandidate;
                    }
                }
            }
        }
        return remoteAddr;
    }

    public String normalizeToPrefix(String ip) {
        if (ip == null || ip.isBlank()) {
            return "0.0.0.0/24";
        }
        try {
            InetAddress address = InetAddress.getByName(ip.trim());
            byte[] bytes = address.getAddress();
            if (bytes.length == 4) {
                // IPv4: /24 subnet -> mask last octet
                int b0 = bytes[0] & 0xFF;
                int b1 = bytes[1] & 0xFF;
                int b2 = bytes[2] & 0xFF;
                return b0 + "." + b1 + "." + b2 + ".0/24";
            } else if (bytes.length == 16) {
                // IPv6: /64 subnet -> mask first 4 words (8 bytes)
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i += 2) {
                    int word = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
                    sb.append(Integer.toHexString(word));
                    if (i < 6) {
                        sb.append(":");
                    }
                }
                sb.append("::/64");
                return sb.toString();
            }
        } catch (Exception ignored) {
            // fallback
        }
        return ip;
    }

    private boolean isTrustedProxy(String remoteAddr) {
        return trustedProxies.contains(remoteAddr.trim());
    }
}
