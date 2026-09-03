## Verdict

**CWE-352 confirmed**: A state-changing handler (`POST /settings`) is reachable without CSRF protection via the unprotected mux on line 37.

## Source

**File**: `main.go`, line 37  
**Line content**: `log.Fatal(http.ListenAndServe(":8080", mux))`

The plaintext HTTP listener on port 8080 serves the unprotected `mux` directly, despite a CSRF-protected `protectedHandler` being available. This creates two separate entry points to the same application: one with CSRF protection (HTTPS on port 8443) and one without (HTTP on port 8080).

## Fix

Replace line 37:
```go
log.Fatal(http.ListenAndServe(":8080", mux))
```

with:
```go
log.Fatal(http.ListenAndServe(":8080", protectedHandler))
```

## Explanation

The application creates CSRF protection via `net/http.CrossOriginProtection` and wraps the mux with it (lines 25–27), storing the result in `protectedHandler`. However, line 37 passes the unwrapped `mux` variable to the plaintext listener, bypassing all CSRF validation.

Per CWE-352 Go guidance: "Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux." Both listeners serve the same mux-registered routes; the HTTPS listener applies protection while the HTTP listener does not. This asymmetry allows an attacker to craft a forged POST request to `http://` endpoints without a valid CSRF token.

Using `protectedHandler` instead ensures that all requests—whether arriving on HTTP or HTTPS—pass through the CSRF validation layer before reaching any state-changing handler.

## Behaviour changes

- HTTP requests to `/settings` (POST) will now be checked for CSRF validation (Fetch-metadata headers). Requests missing or failing validation will be rejected with HTTP 403 Forbidden.
- Legitimate cross-origin requests from origins not in `protection.AddTrustedOrigin()` will be rejected; only same-origin requests and requests from `https://app.example.com` will proceed.
- The plaintext listener will no longer serve unauthenticated state-changing operations; clients must go through the HTTPS endpoint with valid CSRF tokens.
- The redirect-only handler intent is now correctly constrained to trusted origins.
