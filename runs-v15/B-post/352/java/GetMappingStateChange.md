## Verdict

Exploitable. The endpoint at line 38 performs state-changing operation (account deletion) via HTTP GET, which bypasses Spring Security's CSRF protection. CSRF tokens are validated only for non-safe methods (POST, PUT, DELETE, PATCH); GET is safe and skips the validation entirely. An attacker can craft a malicious website or email containing a link to `https://victim-domain.com/account/delete` that forces an authenticated victim to delete their account without their knowledge or consent.

## Source

Unauthenticated attacker-controlled HTTP GET request to `/account/delete` endpoint, sent from a malicious website while the victim is authenticated to the target application.

## Fix

Move the deletion operation from GET to POST, and convert the GET endpoint to return a confirmation page. The confirmation page presents an HTML form with a hidden CSRF token field that POSTs to the new deletion endpoint. This ensures the deletion request carries a valid CSRF token validated by Spring Security's CsrfFilter.

### Vulnerable Code

```java
@GetMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

### Fixed Code

```java
@GetMapping("/account/delete")
public String confirmDelete(Authentication authentication, CsrfToken csrfToken) {
    String csrfParamName = csrfToken.getParameterName();
    String csrfTokenValue = csrfToken.getToken();
    return "<html><body><h1>Delete Account</h1>" +
        "<p>This action cannot be undone. Are you sure?</p>" +
        "<form method=\"POST\" action=\"/account/delete\">" +
        "<input type=\"hidden\" name=\"" + csrfParamName + "\" value=\"" + csrfTokenValue + "\"/>" +
        "<button type=\"submit\">Confirm Deletion</button>" +
        "<a href=\"/\">Cancel</a>" +
        "</form></body></html>";
}

@PostMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

Import added:
```java
import org.springframework.security.web.csrf.CsrfToken;
```

## Explanation

The fix separates the confirmation UI from the deletion operation. The GET endpoint now returns an HTML form containing a CSRF token injected by Spring Security. The form submits via POST to the same `/account/delete` path with the CSRF token, which Spring Security's CsrfFilter validates before the request reaches the handler. The vulnerability is eliminated because the deletion now requires a valid CSRF token that an attacker cannot forge from a cross-origin request. Existing links to `/account/delete` now land on the confirmation page rather than immediately deleting the account, providing a safety step and allowing the user to cancel the operation.

## Behaviour changes

1. **Existing link behavior change**: Previously, following a link to `/account/delete` immediately deleted the account and returned "account deleted". Now it displays a confirmation page requiring an explicit form submission. Users who previously relied on the link-based deletion now receive a confirmation page. This is a security-necessary behavior change that prevents accidental deletions via cross-site forgery and requires one additional user interaction.

2. **Response content-type change**: The GET response is now HTML (inline as a string) rather than plain text. Browsers will render it as a web page instead of displaying raw text.

3. **CsrfToken parameter injection**: The GET handler now receives an additional `CsrfToken` parameter injected by Spring Security. This is a framework-provided dependency injection; no additional configuration is required.

4. **HTTP method for deletion**: The actual deletion now requires POST instead of GET. Clients that have direct links or bookmarks to `/account/delete` expecting immediate deletion will now receive a form page instead. Programmatic API clients must update from GET to POST.
