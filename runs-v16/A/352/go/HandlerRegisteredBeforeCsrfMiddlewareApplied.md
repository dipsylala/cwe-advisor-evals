## Verdict

CONFIRMED

## Source

```go
log.Fatal(http.ListenAndServe(":8080", mux))
```

Line 37 registers the unprotected `mux` on the plaintext HTTP listener, bypassing the CSRF protection middleware that wraps `protectedHandler` on the TLS listener. An attacker can exploit this by crafting a request to the HTTP listener to trigger the state-changing `POST /settings` handler without a valid CSRF token.

## Fix

Replace `mux` with `protectedHandler` on line 37:

```go
log.Fatal(http.ListenAndServe(":8080", protectedHandler))
```

This ensures that CSRF protection is enforced on all listeners, including the plaintext HTTP one.

## Explanation

The application correctly wraps the mux with CSRF protection via `http.NewCrossOriginProtection()` and applies the protected handler to the TLS listener. However, the plaintext HTTP listener (intended as a redirect service) was mistakenly registered with the raw, unprotected mux. This creates two separate entry points: one protected (HTTPS) and one unprotected (HTTP). An attacker can bypass CSRF token validation by directing requests to the HTTP listener instead of HTTPS, allowing them to perform state-changing operations like modifying application settings without authorization. Using the same `protectedHandler` on both listeners ensures consistent protection regardless of which endpoint a request reaches.
