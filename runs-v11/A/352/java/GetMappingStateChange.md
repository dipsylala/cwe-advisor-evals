## Verdict

CWE-352 confirmed. The `/account/delete` endpoint performs an account deletion (a state-changing operation) but is exposed as a `@GetMapping`. Spring Security's CSRF filter only validates tokens on non-safe HTTP methods; GET requests pass through without CSRF token inspection, allowing an attacker to craft a cross-origin request that deletes a user's account when the user visits a malicious page.

## Source

Line 38: `@GetMapping("/account/delete")` maps a state-changing operation to an HTTP method that bypasses CSRF protection.

## Fix

Change the HTTP method mapping from `@GetMapping` to `@PostMapping`:

```java
@PostMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

This ensures Spring Security's CSRF filter validates an X-CSRF-TOKEN header on the request before the endpoint executes. The client must provide a valid CSRF token obtained from the application in advance (typically embedded in a form or retrieved via a prior request).

If the endpoint must remain accessible via GET for backwards compatibility, override the CSRF filter to explicitly exempt only this path using `CsrfConfigurer.ignoringRequestMatchers()` in the `SecurityConfig` class and document why the exemption is safe (though this should only be done after confirming there is no viable POST alternative).

## Explanation

State-changing operations—account deletion, permission changes, data modifications—must use non-safe HTTP methods (POST, PUT, DELETE, PATCH) so that they are subject to CSRF token validation. GET is semantically safe and browsers do not require a token to follow a GET link, so CSRF attacks can force a GET request without user action. Mapping state changes to GET defeats the CSRF protection that Spring Security enforces on the application as a whole. The fix changes the mapping to POST, which forces the client to submit a form or AJAX request that includes the required token, making cross-origin state changes impossible.

