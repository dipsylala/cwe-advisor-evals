## Verdict

CONFIRMED - CWE-352 CSRF vulnerability on line 38. State-changing operation (`accountService.deleteAccount()`) is reachable via GET request, bypassing Spring Security's CSRF token validation which only protects non-safe HTTP methods (POST, PUT, DELETE).

## Source

Attacker-controlled source: HTTP GET request to `/account/delete` from an authenticated user's browser. Attacker crafts a link (e.g., `<img src="http://target/account/delete">`) that triggers account deletion without the user's knowledge or consent.

## Fix

Move the state-changing operation from GET to POST. The GET endpoint should return a confirmation page (safe, no state mutation). The POST endpoint performs the actual deletion and is automatically protected by Spring Security's CSRF filter which validates tokens for non-safe methods.

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

    // GET endpoint renders a confirmation page (safe operation).
    // This endpoint no longer mutates state - the actual deletion is moved
    // to the POST handler below, which is automatically protected by Spring
    // Security's CSRF token requirement.
    @GetMapping("/account/delete")
    public ModelAndView showDeleteConfirmation() {
        return new ModelAndView("delete-confirmation");
    }

    // POST endpoint performs the actual account deletion (state-changing operation).
    // Spring Security's CsrfFilter automatically validates the CSRF token for
    // non-safe HTTP methods like POST.
    @PostMapping("/account/delete")
    public String deleteAccount(Authentication authentication) {
        accountService.deleteAccount(authentication.getName());
        return "account deleted";
    }
}
```

## Explanation

The original code exposes a CSRF vulnerability by performing account deletion via a GET request. Spring Security's CSRF protection (enabled globally in this application) only validates tokens for non-safe HTTP methods (POST, PUT, DELETE, PATCH), treating GET as a safe operation that requires no token. This means an attacker can exploit the user's authenticated session by tricking them into visiting a malicious page with a link to `/account/delete`, causing their account to be silently deleted.

The fix separates the operation into two handlers following the Synchronizer Token Pattern:

1. **GET `/account/delete`**: Changed to return a confirmation view (safe operation, no state mutation). Uses `ModelAndView` to render a template file (`delete-confirmation`) since we're in a `@RestController` context where returning a String would be treated as the response body, not a view name.

2. **POST `/account/delete`**: New handler that performs the actual account deletion. As a POST method, Spring Security's `CsrfFilter` automatically intercepts this request and validates that a valid CSRF token is present in the request (either as `_csrf` parameter or `X-CSRF-TOKEN` header). Without a valid token, the request is rejected with HTTP 403 Forbidden.

This pattern preserves the original convenience feature (users can access `/account/delete` via a simple link in the account settings page) while preventing CSRF attacks: the link now navigates to a confirmation page whose form submits via POST with a CSRF token, instead of directly mutating state via GET.

## Behaviour changes

**Before fix**: 
- GET `/account/delete` → immediately deletes account (no CSRF token required)
- Existing links to `/account/delete` trigger deletion directly

**After fix**:
- GET `/account/delete` → returns confirmation page with a form that submits to POST `/account/delete`
- POST `/account/delete` → deletes account (requires valid CSRF token in request body or header)
- Existing links to `/account/delete` now show a confirmation page instead of immediately deleting; user must confirm by submitting the form

The confirmation page template (`delete-confirmation.html` or equivalent) must exist in the view resolver's configured locations and should include a form that:
- Uses POST method to `/account/delete`
- Includes a hidden input with the CSRF token (e.g., `<input type="hidden" name="_csrf" value="${_csrf.token}" />`)
- Provides a submit button for the user to confirm deletion
