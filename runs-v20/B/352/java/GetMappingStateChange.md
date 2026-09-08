## Verdict

Confirmed - CWE-352 (Cross-Site Request Forgery). `deleteAccount` mutates state (`accountService.deleteAccount(...)`) but is mapped with `@GetMapping`, so it never reaches Spring Security's `CsrfFilter` at all - that filter only inspects non-safe HTTP methods (POST/PUT/DELETE/PATCH). Any authenticated user who loads an attacker-controlled page containing `<img src="https://target/account/delete">` (or is redirected to that URL) has their account deleted, with no token check possible regardless of how well CSRF is configured elsewhere in the app.

## Source

Attacker-crafted cross-site request (any origin) to `GET /account/delete`, riding the victim's authenticated session cookie. `authentication` is the victim's own `Authentication`, resolved from that session by Spring Security - it is not attacker-controlled, so the weakness is entirely in the endpoint's HTTP method, not in any parameter value.

## Fix

### File: AccountController.java

```java
package com.example.accounts.web;

import com.example.accounts.service.AccountService;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
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

    // The "delete my account" link in the account settings page keeps working:
    // it still reaches this GET mapping. It no longer mutates state by itself -
    // it renders a confirmation form whose POST carries the CSRF token to the
    // deleteAccount mapping below, so the actual deletion goes through
    // Spring Security's CsrfFilter like every other mutation in this class.
    @GetMapping(value = "/account/delete", produces = MediaType.TEXT_HTML_VALUE)
    public String confirmDeleteAccount(CsrfToken csrfToken) {
        return "<html><body>"
                + "<p>This will permanently delete your account.</p>"
                + "<form method=\"post\" action=\"/account/delete\">"
                + "<input type=\"hidden\" name=\"" + csrfToken.getParameterName()
                + "\" value=\"" + csrfToken.getToken() + "\">"
                + "<button type=\"submit\">Confirm delete</button>"
                + "</form>"
                + "</body></html>";
    }

    @PostMapping("/account/delete")
    public String deleteAccount(Authentication authentication) {
        accountService.deleteAccount(authentication.getName());
        return "account deleted";
    }
}
```

## Explanation

The finding is a method-verb problem, not a missing-token problem: `CsrfFilter` already validates every POST/PUT/DELETE/PATCH mapping in this class correctly, but it only inspects non-safe methods, so a `@GetMapping` that deletes the account bypasses the check entirely - no token would help here even if one were added to the GET request. The fix moves the mutation off GET: `deleteAccount` is now `@PostMapping("/account/delete")`, so it is covered by the same CsrfFilter/`HttpSessionCsrfTokenRepository` synchronizer-token check already protecting `updateEmail`. The GET route at the same URL is kept, per the existing link to it from the settings page, but its handler (`confirmDeleteAccount`) no longer touches `accountService` - it renders a minimal confirmation form whose action posts back to `/account/delete` with the session's CSRF token embedded as a hidden field. The token is obtained via Spring Security's `CsrfTokenArgumentResolver`, which Spring Boot registers automatically for any Spring MVC controller method that declares a `CsrfToken` parameter (confirmed against the Spring Security reference documentation for "Include the CSRF Token"/MVC integration) - no additional configuration or import beyond `org.springframework.security.web.csrf.CsrfToken` is needed. Because the class stays `@RestController`, the returned `String` is written as the literal HTTP response body rather than resolved as a view name; `produces = MediaType.TEXT_HTML_VALUE` (from `org.springframework.http.MediaType`, spring-web) makes the browser render it as a page instead of plain text, so no template engine or separate `@Controller` is required for this minimal confirmation form. `accountService.deleteAccount(authentication.getName())` is unchanged - same argument, same return value, same caller-visible contract - it is simply invoked from a mapping the CsrfFilter now inspects.

Verification: no build/classpath is available in this single-file case to run `javac` against the real Spring/Spring Security jars, so this was checked by hand against the Spring Security reference documentation (servlet/exploits/csrf.html and servlet/integrations/mvc.html), fetched live: (1) `CsrfToken` is `org.springframework.security.web.csrf.CsrfToken`, exposing `getToken()` and `getParameterName()`; (2) declaring `CsrfToken` as a Spring MVC controller-method parameter is automatically resolved by `CsrfTokenArgumentResolver` when `@EnableWebSecurity` is present, which the file's own comment confirms (`SecurityConfig` with a shared `HttpSecurity` bean) - no new import was introduced that isn't either pre-existing, Spring Security's documented API, or Spring's standard `MediaType` constant. All other symbols (`AccountService`, `Authentication`, `@GetMapping`, `@PostMapping`, `@RestController`) are unchanged from the original file.

## Behaviour changes

- `GET /account/delete` no longer deletes the account by itself. It now returns an HTML confirmation page (a form that POSTs to `/account/delete` with the CSRF token). Any existing link or bookmark that pointed at this URL still resolves and still lets the user delete their account - it now requires one extra click (submitting the confirmation form) instead of deleting immediately on page load.
- Deletion now happens via `POST /account/delete` (new mapping, same URL path, different HTTP method) and is therefore subject to the application's existing CSRF token validation, like `POST /account/email` already was.
- Any non-browser client or script that was calling `GET /account/delete` directly to trigger deletion (rather than following a link from the settings page) will now only receive the confirmation HTML and must separately submit the POST with a valid CSRF token to complete the deletion - this is the intended effect of closing the forgeable-GET weakness, not an incidental regression.
