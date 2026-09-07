## Verdict

Exploitable. The `@GetMapping("/account/delete")` endpoint directly calls `accountService.deleteAccount()` without CSRF token validation. Spring Security's CSRF filter only validates non-safe HTTP methods (POST/PUT/DELETE/PATCH), so GET requests bypass token verification. An attacker can force an authenticated user to delete their account by tricking them into following a malicious link.

## Source

HTTP GET request to `/account/delete` with an authenticated user session. The request source is attacker-controlled (a malicious link the user follows), and the user's browser automatically includes their session cookie.

## Fix

### File: AccountController.java

```java
package com.example.accounts.web;

import com.example.accounts.service.AccountService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

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

    // Convenience endpoint so a "delete my account" link in the account
    // settings page can be reached directly. Returns a confirmation page whose
    // form POSTs to the same path. Because POST is a state-changing method,
    // Spring Security's CsrfFilter validates the token before reaching the
    // PostMapping handler.
    @GetMapping("/account/delete")
    public ModelAndView showDeleteConfirmation(Authentication authentication) {
        return new ModelAndView("delete-confirmation");
    }

    // Performs the actual account deletion. Only reachable by POST requests
    // with a valid CSRF token, never by direct link.
    @PostMapping("/account/delete")
    public String deleteAccount(Authentication authentication) {
        accountService.deleteAccount(authentication.getName());
        return "account deleted";
    }
}
```

## Explanation

The fix implements the Synchronizer Token Pattern by separating the confirmation UI from the state-changing operation. The `@GetMapping` now returns a confirmation view (via `ModelAndView`) that a user can read before committing to deletion. The confirmation page contains an HTML form that POSTs to the same endpoint path. Because POST is a non-safe HTTP method, Spring Security's `CsrfFilter` intercepts the POST request and validates the CSRF token before the `@PostMapping` handler executes. An attacker cannot forge a valid CSRF token, so the account deletion only proceeds when the user explicitly submits the confirmation form from within the application, not when tricked into following an external link.

## Behaviour changes

- **Return type of GET**: Changed from `String` ("account deleted") to `ModelAndView`. The GET endpoint no longer performs deletion; it returns a view object that Spring resolves to an HTML confirmation page template (`delete-confirmation`).
- **HTTP response body for GET**: Changed from the literal string "account deleted" to rendered HTML template. Users will see a confirmation page instead of a success message.
- **Endpoint method for deletion**: Account deletion is now only reachable via POST (new `@PostMapping` method), not GET. This enables CSRF token validation by Spring Security's filter.
- **User interaction flow**: Users who click a "delete account" link now see a confirmation page with a submit button, rather than immediate deletion. They must click the confirmation form's button to proceed.
- **HTTP status codes**: GET /account/delete returns 200 with view template (previously 200 with "account deleted" text). POST /account/delete returns 200 with "account deleted" text (same as original, but now CSRF-protected).

Reason for each change: The separation of confirmation view (GET) from action (POST) is the core CSRF remediation pattern when a state-changing endpoint must remain linkable. This preserves the user experience (a link can reach the page) while enforcing CSRF token validation (the action requires POST).
