## Verdict

CONFIRMED. The endpoint uses `@GetMapping` for a state-changing operation, which bypasses Spring Security's CSRF filter. The `CsrfFilter` only validates non-safe HTTP methods (POST, PUT, DELETE, PATCH); GET requests pass through without token verification. An attacker can forge a request that deletes an authenticated user's account by crafting a link or embedding it in a page.

## Source

Package: `com.example.accounts.web`
Class: `AccountController`
Method: `deleteAccount`
Line: 38
Annotation: `@GetMapping("/account/delete")`

The `deleteAccount` method invokes `accountService.deleteAccount(authentication.getName())`, which mutates state by deleting the user's account. The method is reached via GET, a safe HTTP method, so Spring Security's CSRF filter never validates the request.

## Fix

Change the HTTP method from GET to POST by replacing `@GetMapping` with `@PostMapping`.

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

    // Convenience endpoint for account deletion. Originally mapped to GET to avoid
    // requiring JavaScript, but this bypassed CSRF protection because the filter
    // only validates non-safe methods. Now mapped to POST so the CsrfFilter validates
    // the required CSRF token before processing the deletion.
    // Clients must now submit a form (POST) with the token in the body parameter
    // (_csrf) or in the X-CSRF-TOKEN header, rather than following a simple link.
    @PostMapping("/account/delete")
    public String deleteAccount(Authentication authentication) {
        accountService.deleteAccount(authentication.getName());
        return "account deleted";
    }
}
```

## Explanation

The vulnerability arises because Spring Security's CSRF filter only inspects non-safe HTTP methods. GET is classified as a safe method and bypasses token validation entirely. By changing the endpoint from `@GetMapping` to `@PostMapping`, the request becomes a non-safe method and must pass through `CsrfFilter` validation. The filter will require a valid CSRF token (submitted as a form parameter `_csrf` or HTTP header `X-CSRF-TOKEN`) before the state-changing operation is allowed to proceed. This prevents attackers from forging requests without access to the server-generated token bound to the user's session.

The change is minimal and surgical: only the HTTP method annotation is altered. The method signature, return value, and business logic remain unchanged. The endpoint contract is preserved—it still accepts authentication and returns the same response.

## Behaviour changes

- **Request method change**: Clients can no longer trigger account deletion via GET requests. Attempts to reach the endpoint via GET will receive a 405 Method Not Allowed response.
- **CSRF token requirement**: All POST requests to `/account/delete` must include a valid CSRF token in the request body (parameter name: `_csrf`) or in the `X-CSRF-TOKEN` header, or the request will be rejected with 403 Forbidden.
- **Client UI impact**: If the UI uses a simple `<a>` hyperlink to trigger deletion, it must be changed to a form submission (either HTML form or JavaScript POST request) that includes the CSRF token.
- **Link-based workflows**: Any external links or bookmarks to `/account/delete` as a GET request will no longer work and will return 405. Users accessing the delete action via the UI (form-based) will be unaffected because the form will include the token.
