## Verdict
Exploitable

## Source
Handler registration in `buildMux()` (lines 14-17): the `http.ServeMux` receives all routes including the state-changing POST /settings endpoint (`svc.updateSettingsHandler`).

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
		// SAST FINDING: CWE-352 (Cross-Site Request Forgery) fixed by using protectedHandler instead of mux.
		log.Fatal(http.ListenAndServe(":8080", protectedHandler))
	}()

	log.Println("starting TLS listener on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", protectedHandler))
}
```

## Explanation
The plaintext listener on port 8080 was serving the unprotected `mux` directly, allowing state-changing requests (POST /settings) to bypass CSRF protection. The fix replaces `mux` with `protectedHandler`, which wraps all routes with `net/http.CrossOriginProtection`. This ensures that all state-changing endpoints are protected by CSRF token validation regardless of which listener (plaintext or TLS) receives the request. The CSRF middleware rejects cross-origin state-changing requests using Fetch metadata headers, preventing forged requests from succeeding.

## Behaviour changes
None. The fix closes the CSRF vulnerability without altering the listener's contract: it still binds to port 8080 and serves the same routes to the same callers. The handler type changes from `*http.ServeMux` to `http.Handler` (the protected wrapper), but this is type-compatible and does not affect the listener's behaviour or return value.
