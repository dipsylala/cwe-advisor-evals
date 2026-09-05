## Verdict

Exploitable. State-changing handlers (POST /settings) registered on `mux` are accessible through the unprotected HTTP listener on line 37, bypassing the CSRF protection applied only to the HTTPS listener.

## Source

The `mux` variable defined in `buildMux()` (line 22) contains state-changing handlers registered without CSRF middleware wrapping. Line 37 serves this unprotected mux on the plaintext HTTP port.

## Fix

**Vulnerable code (line 34-38):**
```go
go func() {
    log.Println("starting plaintext listener on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}()
```

**Fixed code:**
```go
go func() {
    log.Println("starting plaintext listener on :8080")
    log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        url := "https://app.example.com:8443" + r.RequestURI
        http.Redirect(w, r, url, http.StatusMovedPermanently)
    })))
}()
```

## Explanation

The plaintext listener should serve only a redirect handler that forwards HTTP requests to the HTTPS endpoint. The original code mistakenly serves the full `mux`, which includes the unprotected `POST /settings` handler. By replacing it with a handler that redirects all requests to HTTPS, all state-changing operations are forced through the CSRF-protected HTTPS listener, eliminating the bypass. This matches the stated intent in the code comment that the plaintext listener "was supposed to carry a small redirect handler."

## Behaviour changes

- The plaintext HTTP listener on port 8080 now redirects all requests to HTTPS instead of serving the full application. This is the intended behavior per the code comment and closes the CSRF bypass. Clients connecting to HTTP are transparently redirected to HTTPS with status 301 (MovedPermanently), which is standard HTTP redirect semantics and does not break any legitimate use case since all application endpoints should be accessed over HTTPS for security.
