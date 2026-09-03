## Verdict

Real vulnerability confirmed. The endpoint uses `@GetMapping` for a state-changing operation (account deletion), which bypasses Spring Security's CSRF protection. CSRF filters validate only non-safe HTTP methods; GET is treated as safe and never checked. An attacker can craft a malicious link that forces an authenticated user to delete their account.

## Source

File: AccountController.java, line 38
- Endpoint: `/account/delete`
- Sink: `accountService.deleteAccount(authentication.getName())`
- HTTP Method: GET (incorrect for state-changing operation)
- Authentication: Present (Authentication parameter), but CSRF token validation is skipped
- Issue: The endpoint modifies server state (deletes account) but is unreachable via POST/DELETE, so CSRF protection does not apply

## Fix

Change the HTTP method from GET to DELETE. This forces the client to submit a state-changing request, which Spring Security's CSRF filter will validate.

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

Spring Security's CSRF filter protects only non-safe HTTP methods (POST, PUT, DELETE, PATCH) by requiring a valid CSRF token. GET is treated as safe/idempotent and exempt from token validation. When a state-changing operation like account deletion is reachable via GET, an attacker can bypass CSRF protection by simply crafting a URL and tricking an authenticated user into clicking it (or embedding it in an image tag).

Changing the endpoint to `@DeleteMapping` makes the operation a non-safe method, which Spring Security's CSRF filter will then validate. Any request to delete the account must now include a valid CSRF token, preventing cross-site forgery attacks.

## Behaviour changes

- HTTP method changes from GET to DELETE
- Clients must now use DELETE method and provide valid CSRF token in request header (X-CSRF-TOKEN or X-XSRF-TOKEN)
- Requests without valid CSRF token receive 403 Forbidden response (enforced by Spring Security)
- Browsers cannot issue DELETE requests via simple HTML forms or image tags, significantly reducing attack surface
- Response and business logic remain unchanged
