package com.burnbox.session;

import com.burnbox.identity.BurnboxOidcUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;
import java.util.UUID;

@Controller
@RequestMapping("/account/sessions")
public class SessionManagementController {

    private final UserSessionService sessionService;

    public SessionManagementController(UserSessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping
    public String listSessions(
            @AuthenticationPrincipal BurnboxOidcUser oidcUser,
            HttpServletRequest request,
            Model model
    ) {
        if (oidcUser == null) {
            return "redirect:/login";
        }

        UUID userId = oidcUser.getAppUser().id();
        List<UserSessionMeta> sessions = sessionService.listActiveSessions(userId);
        String currentSessionId = request.getSession(false) != null ? request.getSession(false).getId() : "";

        model.addAttribute("sessions", sessions);
        model.addAttribute("currentSessionId", currentSessionId);
        model.addAttribute("user", oidcUser.getAppUser());

        return "account-sessions";
    }

    @PostMapping("/{sessionId}/revoke")
    public String revokeSession(
            @PathVariable("sessionId") String sessionId,
            @AuthenticationPrincipal BurnboxOidcUser oidcUser,
            HttpServletRequest request
    ) {
        if (oidcUser == null) {
            return "redirect:/login";
        }

        UUID userId = oidcUser.getAppUser().id();
        sessionService.revokeSession(userId, sessionId);

        String currentSessionId = request.getSession(false) != null ? request.getSession(false).getId() : "";
        if (sessionId.equals(currentSessionId)) {
            request.getSession().invalidate();
            return "redirect:/login";
        }

        return "redirect:/account/sessions?revoked=true";
    }

    @PostMapping("/revoke-others")
    public String revokeOthers(
            @AuthenticationPrincipal BurnboxOidcUser oidcUser,
            HttpServletRequest request
    ) {
        if (oidcUser == null) {
            return "redirect:/login";
        }

        UUID userId = oidcUser.getAppUser().id();
        String currentSessionId = request.getSession(false) != null ? request.getSession(false).getId() : "";

        sessionService.revokeOtherSessions(userId, currentSessionId);

        return "redirect:/account/sessions?revokedOthers=true";
    }
}
