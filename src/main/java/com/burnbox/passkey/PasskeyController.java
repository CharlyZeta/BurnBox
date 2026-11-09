package com.burnbox.passkey;

import com.burnbox.identity.BurnboxOidcUser;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Controller
@RequestMapping("/account/passkeys")
public class PasskeyController {

    private final PasskeyService passkeyService;

    public PasskeyController(PasskeyService passkeyService) {
        this.passkeyService = passkeyService;
    }

    @GetMapping
    public String listPasskeys(
            @AuthenticationPrincipal BurnboxOidcUser oidcUser,
            Model model
    ) {
        if (oidcUser == null) {
            return "redirect:/login";
        }

        UUID userId = oidcUser.getAppUser().id();
        List<PasskeyCredential> passkeys = passkeyService.listPasskeys(userId);

        model.addAttribute("passkeys", passkeys);
        model.addAttribute("user", oidcUser.getAppUser());

        return "account-passkeys";
    }

    @PostMapping("/{credIdHex}/revoke")
    public String revokePasskey(
            @PathVariable("credIdHex") String credIdHex,
            @AuthenticationPrincipal BurnboxOidcUser oidcUser
    ) {
        if (oidcUser == null) {
            return "redirect:/login";
        }

        UUID userId = oidcUser.getAppUser().id();
        byte[] credentialId = HexFormat.of().parseHex(credIdHex);

        passkeyService.revokePasskey(userId, credentialId);

        return "redirect:/account/passkeys?revoked=true";
    }
}
