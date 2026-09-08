## Verdict

CWE-352 vulnerability confirmed. The `deleteAccount` endpoint performs a state change (account deletion) but is mapped to GET, which bypasses Spring Security's CSRF filter. Changing to POST restores CSRF protection.

## Source

Line 38 in `AccountController.java`: `@GetMapping("/account/delete")` exposes a state-changing operation via an HTTP method that Spring Security treats as safe and does not require CSRF token validation.

## Fix

### File: AccountController.java

```java
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
    @PostMapping("/account/delete")
    public String deleteAccount(Authentication authentication) {
        accountService.deleteAccount(authentication.getName());
        return "account deleted";
    }
}
```

## Explanation

The vulnerability arises because account deletion is a state-changing operation that must be protected against cross-site request forgery. Spring Security's CsrfFilter only validates tokens on non-safe HTTP methods (POST, PUT, DELETE, PATCH); GET requests bypass this check entirely.

By changing `@GetMapping` to `@PostMapping` on line 38, the endpoint now requires valid CSRF token validation before the account deletion proceeds. The client must provide the token via the `X-CSRF-TOKEN` header or request parameter, preventing an attacker from forging a request through a victim's browser.

This change preserves the endpoint's functionality while restoring the CSRF protection that Spring Security already enforces application-wide on all other state-changing operations in this controller.
