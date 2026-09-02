package com.example.accounts.web;

import com.example.accounts.service.AccountService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Account self-service endpoints. Spring Security's CSRF protection is enabled
 * application-wide via SecurityConfig (see the shared HttpSecurity bean), so
 * every POST/PUT/DELETE/PATCH mapping in this controller requires a valid
 * X-CSRF-TOKEN. That protection only inspects non-safe HTTP methods, so a
 * state change reachable through GET never passes through the CsrfFilter's
 * token check at all.
 */
@RestController
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PostMapping("/account/email")
    public String updateEmail(Authentication authentication, String newEmail) {
        accountService.updateEmail(authentication.getName(), newEmail);
        return "email updated";
    }

    // Convenience endpoint added so a "delete my account" link in the account
    // settings page doesn't need a JavaScript-submitted form. Because it is
    // mapped to GET, Spring Security's CsrfFilter treats it as a safe method
    // and never asks for a token here, even though the filter is active and
    // correctly configured for every other mapping in this class.
    // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    @GetMapping("/account/delete")
    public String deleteAccount(Authentication authentication) {
        accountService.deleteAccount(authentication.getName());
        return "account deleted";
    }
}
