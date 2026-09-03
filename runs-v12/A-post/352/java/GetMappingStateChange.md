## Verdict

The finding is a confirmed CWE-352 (Cross-Site Request Forgery) vulnerability. The `deleteAccount` endpoint performs a state-changing operation but is mapped to GET, which bypasses Spring Security's CSRF protection that only applies to non-safe HTTP methods.

## Source

```java
@GetMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

Line 38 declares the endpoint mapping. The vulnerability lies in the choice of HTTP method: account deletion is a state-changing operation that must be protected against CSRF, but `@GetMapping` treats the request as a safe method, so Spring Security's CSRF filter never applies the token check at this endpoint.

## Fix

Change `@GetMapping` to `@PostMapping`:

```java
@PostMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

Update the client to submit the request as POST instead of GET. If this endpoint is called from an HTML form or frontend, ensure the form method is `post` and the CSRF token is included (Spring Security's CSRF filter will require it automatically).

## Explanation

State-changing operations must use POST, PUT, PATCH, or DELETE — never GET. Spring Security's CSRF protection filters non-safe HTTP methods by default, requiring a valid X-CSRF-TOKEN header for requests that modify state. Using `@GetMapping` for account deletion creates a gap: the endpoint appears to be protected by the application-wide CSRF configuration, but the filter skips GET requests entirely, leaving the action undefended.

The fix enforces that deletion requires a POST request, which automatically engages Spring Security's token validation. The attacker cannot trigger the deletion through a simple image URL or cross-origin GET request; the browser will enforce same-origin policy for form submissions, and any legitimate deletion request must carry a valid CSRF token extracted from the page the user was already viewing.
