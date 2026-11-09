package com.burnbox.audit;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;
import java.util.UUID;

/**
 * Controller for authenticated user security audit log view (BR-006, AF-04).
 */
@Controller
@RequestMapping("/account/events")
public class AuditController {

    private final SecurityEventRepository repository;
    private final AuditChainVerifier verifier;

    public AuditController(SecurityEventRepository repository, AuditChainVerifier verifier) {
        this.repository = repository;
        this.verifier = verifier;
    }

    @GetMapping
    public String viewMyEvents(Authentication authentication, HttpServletResponse response, Model model) {
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/login";
        }

        UUID userId = extractUserId(authentication);
        if (userId == null) {
            return "redirect:/login";
        }

        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Robots-Tag", "noindex, nofollow");

        List<SecurityEventRecord> userEvents = repository.findByActorUserId(userId, 100);
        AuditVerificationResult integrityResult = verifier.verifyChain();

        model.addAttribute("events", userEvents);
        model.addAttribute("integrity", integrityResult);

        return "account-events";
    }

    private UUID extractUserId(Authentication auth) {
        try {
            return UUID.fromString(auth.getName());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
