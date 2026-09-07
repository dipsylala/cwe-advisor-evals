## Verdict
The account deletion endpoint is exposed as an unsafe GET request, making it vulnerable to cross-site request forgery (CSRF). A cross-site attacker can trigger account deletion by embedding a link, image, or navigation in a malicious page. The victim's session cookie is automatically sent with the request, causing their account to be deleted without explicit consent or origin validation.

## Source
File: `account_routes.go`, line 31

The vulnerable code registers account deletion as a GET request:
```go
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
```

The route bypasses CSRF protection because `http.CrossOriginProtection` middleware only validates non-safe HTTP methods (POST, PUT, DELETE, PATCH). GET is treated as a safe, cacheable operation by design, so the middleware never applies origin or Sec-Fetch-Site checks to it.

## Fix
Change line 31 to use POST instead of GET, and wrap it with the CrossOriginProtection middleware:
```go
mux.Handle("POST /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
```

Remove or update the deleteAccountHandler to accept POST instead of GET in its implementation, as needed. The endpoint should require an explicit POST request from the same origin, with Sec-Fetch-Site validation enforced by the middleware.

## Explanation
Account deletion is a state-changing operation that must not be triggerable by a simple GET request from a cross-origin context. By changing the HTTP method to POST and applying `http.CrossOriginProtection`, the endpoint now:

1. **Requires an explicit form submission or XHR request** — a simple link or image tag cannot trigger it.
2. **Validates Sec-Fetch-Site headers** — the middleware rejects requests where `Sec-Fetch-Site` is `cross-site`, confirming the request originated from the same origin as the application.
3. **Aligns with HTTP semantics** — POST signifies a request that modifies server state, while GET is reserved for safe, idempotent operations.

This is the primary defense: using the correct HTTP method and the framework's built-in origin validation. No additional CSRF token is needed when `http.CrossOriginProtection` is in place for POST requests, though tokens provide defense-in-depth for browsers that do not support Fetch metadata headers.
