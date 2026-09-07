## Verdict

CONFIRMED: The state-changing handler `POST /settings` (registered in `buildMux`) is exposed on an unprotected HTTP listener, bypassing CSRF middleware.

## Source

The `updateSettingsHandler` (settings_service.go lines 40-50) mutates account settings without verifying CSRF tokens. The handler is registered on `http.ServeMux` at `POST /settings` (main.go line 16).

## Fix

### File: main.go

```go
package main

import (
	"log"
	"net/http"
)

// buildMux registers every application route, including the
// state-changing settings update, on a single ServeMux. Routing here
// is not the problem: whichever handler ends up serving requests gets
// all of these routes regardless of which variable points at the mux.
func buildMux(svc *SettingsService) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthCheckHandler)
	mux.HandleFunc("GET /settings", svc.viewSettingsHandler)
	mux.HandleFunc("POST /settings", svc.updateSettingsHandler)
	return mux
}

func main() {
	svc := NewSettingsService()
	mux := buildMux(svc)

	// Wrap the mux with CSRF protection before the application goes live.
	protection := http.NewCrossOriginProtection()
	protection.AddTrustedOrigin("https://app.example.com")
	protectedHandler := protection.Handler(mux)

	// A plaintext listener that exists only to bounce http:// visitors
	// to https://. It was supposed to carry a small redirect handler,
	// but whoever wrote it reached for the already-in-scope mux
	// variable instead, so it ends up serving the entire application -
	// settings update included - with no CSRF protection at all.
	go func() {
		log.Println("starting plaintext listener on :8080")
		// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
		log.Fatal(http.ListenAndServe(":8080", protectedHandler))
	}()

	log.Println("starting TLS listener on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", protectedHandler))
}
```

## Explanation

The vulnerability was that line 37 served the unprotected `mux` on the HTTP listener. This allowed requests to reach the state-changing `POST /settings` handler without CSRF validation, since the CSRF middleware (created at line 27 via `protection.Handler(mux)`) was only applied to the HTTPS listener (line 41).

The fix changes line 37 to serve `protectedHandler` instead of `mux`. Both listeners now use the same CSRF-wrapped handler, ensuring that all state-changing requests—whether arriving over HTTP or HTTPS—are validated against forged cross-site requests. Go 1.25.1+ `net/http.CrossOriginProtection` checks Fetch Metadata headers and rejects same-site-postable state-changing requests that lack a valid origin.

## Behaviour changes

The HTTP listener on port 8080 now enforces CSRF validation on all state-changing requests. Legitimate requests that include valid Fetch Metadata headers or Referer values matching the trusted origin continue to succeed. Cross-origin state-changing requests (e.g., forged POST requests from another website) are rejected with HTTP 403 Forbidden, eliminating the CSRF attack surface that previously existed on the plaintext listener.
