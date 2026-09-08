## Verdict

CONFIRMED: CWE-352 (Cross-Site Request Forgery). The plaintext HTTP listener on line 37 serves the unprotected `mux` instead of the CSRF-protected `protectedHandler`, allowing state-changing operations (POST /settings) to be executed without CSRF validation.

## Source

Line 37 in main.go is the sink where the vulnerable mux is exposed to the network. The data flow is:

1. `buildMux()` registers all handlers including the POST /settings state-change endpoint (line 16)
2. `http.NewCrossOriginProtection()` creates protection and wraps the mux as `protectedHandler` (lines 25-27)
3. The TLS listener correctly uses `protectedHandler` (line 41)
4. The HTTP listener on line 37 passes `mux` directly to `ListenAndServe`, bypassing all CSRF protection

The vulnerability exists because the HTTP listener is bound to the unprotected mux variable, exposing state-changing handlers to CSRF attacks.

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

The fix replaces `mux` with `protectedHandler` on line 37. This ensures that all handlers, including state-changing endpoints, are protected by CSRF validation regardless of which listener serves them.

Both listeners now serve the same protected handler chain, so CSRF tokens are enforced consistently. The HTTP listener still functions as a redirect endpoint, but any requests that reach the state-changing handlers are first validated against CSRF policies defined by `http.NewCrossOriginProtection()`.

The fix is minimal and surgical: it changes only what is necessary to close the CSRF gap, without refactoring the redirect listener intent or modifying any other logic.
