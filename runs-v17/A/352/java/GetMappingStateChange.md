## Verdict

**Confirmed CSRF vulnerability.** Line 38 maps a state-changing operation (`deleteAccount`) to `@GetMapping`, which bypasses Spring Security's CSRF token validation. GET requests are treated as safe HTTP methods and never inspected by the `CsrfFilter`, allowing a cross-site request to delete an authenticated user's account without their explicit consent.

## Source

Line 38: `@GetMapping("/account/delete")`

The endpoint performs account deletion—a state-changing operation with permanent consequences—but uses a GET HTTP method. Spring Security's CSRF protection only validates tokens on non-safe HTTP methods (POST, PUT, DELETE, PATCH). Because this operation is mapped to GET, it is exempt from CSRF token checks despite Spring Security being enabled application-wide.

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

The fix changes line 38 from `@GetMapping` to `@PostMapping`. This forces the `/account/delete` endpoint to accept only POST requests rather than GET requests.

**Why this fixes the vulnerability:**

1. **CSRF protection scope**: Spring Security's `CsrfFilter` only validates CSRF tokens for non-safe HTTP methods. Safe methods (GET, HEAD, OPTIONS, TRACE) are assumed to be idempotent and read-only, so the filter skips them.

2. **GET is inherently unsafe for state changes**: Even though HTTP specifications classify GET as "safe," the endpoint violated this contract by performing a destructive operation. A malicious website can embed a simple GET request (e.g., via `<img src="https://victim.com/account/delete">`) and trigger the action automatically when a logged-in user visits it.

3. **POST enforces token validation**: POST is a non-safe method, so Spring Security's `CsrfFilter` will require an `X-CSRF-TOKEN` header or `_csrf` parameter. Since a cross-origin POST request cannot access the CSRF token from the victim's page (due to Same-Origin Policy), the attacker cannot forge the request.

**Frontend implication**: The account deletion link/button must now submit an HTML form via POST instead of navigating directly to the URL. This is the standard CSRF-safe pattern for state-changing operations in web applications.
