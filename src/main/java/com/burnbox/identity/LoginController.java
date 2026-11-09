package com.burnbox.identity;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            Model model
    ) {
        if ("collision".equals(error)) {
            return "login-collision";
        }
        if (error != null) {
            model.addAttribute("error", "No se pudo completar el inicio de sesión. Verifique su cuenta o intente nuevamente.");
        }
        return "login";
    }
}
