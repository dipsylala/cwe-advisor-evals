## Verdict

Confirmed. `AccountController.deleteAccount` performs a state-changing operation (permanent account deletion) behind a `@GetMapping`. Spring Security's `CsrfFilter` only inspects non-safe HTTP methods (POST/PUT/DELETE/PATCH) and treats GET as safe, so this endpoint is never asked for an `X-CSRF-TOKEN` even though CSRF protection is enabled and correctly configured for every other mapping in the class. An attacker can trigger it purely by getting an authenticated victim's browser to issue a GET request to `/account/delete` - for example via `<img src="https://victim-app/account/delete">` embedded in any page the victim visits, with no form submission or script required.

## Source

- `E:/Github/cwe-advisor/evals/cases/352/java/GetMappingStateChange/AccountController.java:38-42` - `@GetMapping("/account/delete")` mapped to `deleteAccount(Authentication authentication)`, which calls `accountService.deleteAccount(authentication.getName())` on line 40. The authenticated principal is taken from the session-bound `Authentication` object, not from any per-request proof of intent, so any GET to this URL from the victim's authenticated browser session executes the deletion.

## Fix

### File: AccountController.java
```java
package com.example.accounts.web;

import com.example.accounts.service.AccountService;
import org.springframework.security.core.Authentication;
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

    // Account deletion is a state change, so it is mapped to POST like the other
    // mutating endpoints in this class. That puts it back through Spring
    // Security's CsrfFilter, which only inspects non-safe HTTP methods, so the
    // caller must now present a valid X-CSRF-TOKEN. The "delete my account" link
    // in the account settings page must be replaced with a form (or a
    // JavaScript-submitted request that attaches the CSRF token) that POSTs here
    // instead of navigating to a GET URL.
    @PostMapping("/account/delete")
    public String deleteAccount(Authentication authentication) {
        accountService.deleteAccount(authentication.getName());
        return "account deleted";
    }
}
```

## Explanation

The root cause is not missing CSRF protection - the shared `HttpSecurity` bean already enables it - but a state-changing action mapped to a safe HTTP method, which the `CsrfFilter` deliberately skips (GET/HEAD/OPTIONS/TRACE are exempt because they are expected to be side-effect-free per HTTP semantics). Changing the annotation from `@GetMapping` to `@PostMapping` puts the endpoint back under the filter's token check without touching `SecurityConfig` or any other mapping, and matches the pattern already used by the sibling `updateEmail` endpoint in the same class.

This is a breaking change for the client that currently reaches the endpoint via a plain hyperlink: a `<a href="/account/delete">` navigation cannot carry a request body or a CSRF header. The "delete my account" affordance in the account settings page must become a `<form method="post">` (Spring's CSRF token tag/hidden field is rendered automatically when using Spring's form tag library or Thymeleaf's Spring Security dialect) or a JavaScript-submitted POST that reads the token from the CSRF cookie/meta tag and attaches it as `X-CSRF-TOKEN`. No allowlist, confirmation-page, or double-submit-cookie workaround is needed or appropriate here: the existing CsrfFilter configuration is correct, and the only defect was routing a mutation through a method the filter is specified to exempt.
