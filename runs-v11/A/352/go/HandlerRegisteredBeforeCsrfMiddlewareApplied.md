## Verdict
CONFIRMED - The CSRF-protected handler is registered only on the HTTPS listener while an unprotected handler serves the same routes on HTTP.

## Source
Line 37 registers the plaintext HTTP listener with the unprotected `mux`, bypassing the CSRF middleware that was applied to `protectedHandler` on line 27. The state-changing POST endpoint remains accessible without CSRF token validation on the HTTP listener.

## Fix
Replace `mux` with a dedicated HTTPS redirect handler on the plaintext listener. Create a separate handler that redirects all HTTP requests to the equivalent HTTPS URL, ensuring no application logic runs on the unprotected channel:

```go
redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    target := "https://" + r.Host + r.RequestURI
    http.Redirect(w, r, target, http.StatusMovedPermanently)
})
```

Then use `redirectHandler` instead of `mux` on line 37:
```go
log.Fatal(http.ListenAndServe(":8080", redirectHandler))
```

## Explanation
The application correctly applies CSRF protection to the HTTPS listener by wrapping the mux with `http.NewCrossOriginProtection()`, but the unprotected `mux` is still exposed on HTTP (port 8080). An attacker can bypass CSRF protection by making requests directly to the HTTP endpoint, which lacks token validation. Since the plaintext listener was intended only to redirect visitors to HTTPS (not serve the full application), it should use a simple redirect handler instead of the application mux. This ensures all application routes are protected by the CSRF middleware and no request bypasses validation.
