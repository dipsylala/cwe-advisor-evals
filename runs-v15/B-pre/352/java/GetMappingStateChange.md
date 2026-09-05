## Verdict

Exploitable

## Source

GET request to `/account/delete` endpoint, attacker-controlled via cross-site request.

## Fix

**Vulnerable code:**
```java
@GetMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

**Fixed code:**
```java
@DeleteMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

## Explanation

The vulnerability is that `@GetMapping` creates an endpoint reachable via GET requests, which bypass Spring Security's CSRF filter. GET is treated as a safe method by the CsrfFilter, so no token validation occurs even when CSRF protection is enabled globally. By changing the mapping to `@DeleteMapping`, the endpoint now requires the DELETE HTTP method, which is a state-changing method that Spring Security's CsrfFilter validates. Requests to this endpoint must now include a valid CSRF token in the `X-CSRF-TOKEN` header, eliminating the CSRF vulnerability.

## Behaviour changes

Clients can no longer trigger account deletion via a simple GET request or link. The endpoint now requires:
- HTTP DELETE method (not GET)
- Valid CSRF token in the `X-CSRF-TOKEN` header (provided by Spring Security)

This is an intentional security-required breaking change. Existing links that perform account deletion (e.g., `<a href="/account/delete">`) will no longer work and require either: (1) conversion to a form with POST/DELETE method and embedded CSRF token, or (2) a two-step flow where GET returns a confirmation form/page, and the actual deletion is handled by a separate DELETE or POST endpoint with CSRF protection enabled.
