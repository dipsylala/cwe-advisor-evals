## Verdict

CONFIRMED. The state-changing POST /settings handler is registered on the unprotected mux and served on the plaintext HTTP listener without CSRF protection, allowing cross-origin requests to bypass validation.

## Source

Line 12-18: `buildMux()` registers POST /settings (state-changing handler) on mux.
Line 37: `http.ListenAndServe(":8080", mux)` serves the same unprotected mux on HTTP.
Line 25-27: CSRF protection is created but applied only to `protectedHandler`, not to the mux served on line 37.

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
	// to https://. Serve only the redirect; do not reach for the mux
	// variable, which includes state-changing handlers unprotected.
	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := "https://" + r.Host + r.RequestURI
		http.Redirect(w, r, url, http.StatusMovedPermanently)
	})

	go func() {
		log.Println("starting plaintext listener on :8080")
		log.Fatal(http.ListenAndServe(":8080", redirectHandler))
	}()

	log.Println("starting TLS listener on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", protectedHandler))
}
```

## Explanation

The vulnerability was that the unprotected `mux` (containing all application routes including the state-changing POST /settings handler) was served on the plaintext HTTP listener. This allowed attackers to craft cross-origin POST requests to http://app.example.com:8080/settings and bypass CSRF validation entirely, since the requests never reach the `protection.Handler(mux)` wrapper.

The fix creates a dedicated `redirectHandler` that only redirects HTTP requests to HTTPS. This ensures:
1. State-changing handlers are never served outside the CSRF-protected handler
2. The plaintext listener fulfills its intended purpose: redirecting HTTP traffic to HTTPS
3. All requests for application functionality go through `protectedHandler`, which validates CSRF tokens and enforces Fetch metadata checks for cross-origin state-changing requests

The fix eliminates the parallel unprotected mux path by replacing it with a simple redirect that matches the original intent expressed in the code comment.

## Behaviour changes

- HTTP requests to /settings (and any other application route) now redirect to HTTPS instead of being served directly. This is a behavior change, but it aligns with the original intent (the comment states the listener "was supposed to carry a small redirect handler") and is the correct security behavior: state-changing operations should never be served over HTTP.
- A client making an HTTP POST request to /settings will now receive a 301 redirect response instead of the settings update response or a 403 CSRF error. This is correct: the client should follow the redirect to HTTPS and resubmit through the secure connection with proper CSRF token handling.
