package com.example.accounts.web;

import com.example.accounts.service.AccountService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Profile endpoint called by the SPA after it reads the XSRF-TOKEN cookie
 * and sends it back as the X-XSRF-TOKEN header, per the frontend's Axios
 * defaults. With the default XorCsrfTokenRequestAttributeHandler still in
 * place server-side, the raw cookie value the browser sends never matches
 * the BREACH-encoded value CsrfFilter compares it against, so every
 * legitimate profile update from the SPA is rejected with 403.
 */
@RestController
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PatchMapping("/api/account/profile")
    public ProfileResult updateProfile(@AuthenticationPrincipal User principal,
                                        @RequestBody ProfileUpdateRequest request) {
        accountService.updateDisplayName(principal.getUsername(), request.displayName());
        return new ProfileResult("updated");
    }

    public record ProfileUpdateRequest(String displayName) {
    }

    public record ProfileResult(String status) {
    }
}
