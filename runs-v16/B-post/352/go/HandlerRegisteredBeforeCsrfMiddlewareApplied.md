## Verdict

CONFIRMED. The plaintext HTTP listener on line 37 serves the full application via the unprotected `mux` instead of the CSRF-protected `protectedHandler`, bypassing all CSRF defenses for the state-changing endpoint `POST /settings` when accessed over HTTP.

## Source

The vulnerability arises from a handler-registration ordering error:

- Line 22-27: `mux` is created and all routes registered, then wrapped with `protection.Handler(mux)` to create `protectedHandler`
- Line 37: The plaintext HTTP listener uses `mux` directly, not `protectedHandler`
- Line 41: The TLS listener correctly uses `protectedHandler`

An attacker exploits this by crafting a cross-site request that targets the HTTP endpoint. The browser includes the user's session cookie, `mux` processes the request without CSRF validation, and the settings update succeeds.

## Fix

**Vulnerable code (line 37):**
```go
log.Fatal(http.ListenAndServe(":8080", mux))
```

**Fixed code:**
```go
log.Fatal(http.ListenAndServe(":8080", protectedHandler))
```

## Explanation

The fix replaces the bare `mux` handler with `protectedHandler` on the plaintext listener. This ensures that all requests—including the redirect traffic—flow through `net/http.CrossOriginProtection`, which rejects cross-origin state-changing requests using Fetch metadata headers. Both listeners now enforce the same CSRF policy, closing the bypass where state-changing operations were reachable without validation.

The `protectedHandler` variable, created on line 27, is already in scope and wraps `mux` with the configured protection, so no additional setup or imports are required. The change is strictly a handler substitution.

## Behaviour changes

- Requests to the HTTP listener's state-changing endpoints now undergo CSRF validation identical to the TLS listener, matching the application's security posture.
- Legitimate redirect traffic and healthcheck requests that do not mutate state are unaffected.
- Any cross-origin POST, PUT, DELETE, or PATCH request to the HTTP listener without valid Fetch metadata is rejected with HTTP 403.
