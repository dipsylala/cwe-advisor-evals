## Verdict
CONFIRMED

## Source
Line 37 serves the unprotected `mux` handler on the plaintext HTTP listener, bypassing CSRF protection that was applied only to `protectedHandler` on line 27.

```go
log.Fatal(http.ListenAndServe(":8080", mux))
```

The `protectedHandler` wrapping `mux` with `http.CrossOriginProtection()` is applied only to the TLS listener (line 41), leaving the HTTP listener completely unprotected. An attacker can forge cross-site requests to any route, including the state-changing `POST /settings` endpoint.

## Fix
Replace line 37 with:

```go
log.Fatal(http.ListenAndServe(":8080", http.RedirectHandler("https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)))
```

Alternatively, create a minimal redirect-only handler and pass it instead of the full application mux:

```go
redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
})
log.Fatal(http.ListenAndServe(":8080", redirectHandler))
```

Or, if the HTTP listener must serve the full application, wrap it with the same protection:

```go
log.Fatal(http.ListenAndServe(":8080", protectedHandler))
```

## Explanation
CSRF protection is only effective if applied consistently to all request paths that handle state-changing operations. The code correctly creates a `protectedHandler` that wraps the application mux with `http.CrossOriginProtection()`, but then serves the unprotected `mux` on a separate listener.

An attacker on an external website can craft a form or script that makes a `POST` request to the plaintext listener (via redirects or direct access if the application is accessed over HTTP at any point), bypassing the CSRF token validation that would occur on the protected TLS listener. This allows the attacker to perform authenticated actions like modifying settings without the user's explicit consent.

The fix ensures that either (1) the plaintext listener only redirects traffic to HTTPS without serving application logic, or (2) the plaintext listener uses the same protected handler as HTTPS. The redirect-only approach is simpler and more secure, preventing the HTTP listener from ever handling sensitive operations.
