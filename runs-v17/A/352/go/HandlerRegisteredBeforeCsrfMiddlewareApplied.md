## Verdict
CONFIRMED. The plaintext HTTP listener on port 8080 serves the unprotected mux, exposing the state-changing POST /settings endpoint to CSRF attacks. The CSRF protection is only applied to the TLS listener on port 8443.

## Source
Line 37: `log.Fatal(http.ListenAndServe(":8080", mux))` serves the entire application without CSRF protection on the plaintext listener.

The vulnerability occurs because:
1. `protectedHandler` wraps `mux` with CSRF protection (line 27)
2. `protectedHandler` is used only on the TLS listener (line 41)
3. The unprotected `mux` is used on the plaintext HTTP listener (line 37)
4. An attacker can send a CSRF request to http://localhost:8080/settings to modify application state

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

// redirectToHTTPS is a minimal handler that redirects all requests to HTTPS.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	url := "https://" + r.Host + r.RequestURI
	http.Redirect(w, r, url, http.StatusMovedPermanently)
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
		// FIXED: Use a redirect handler instead of the unprotected mux
		log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(redirectToHTTPS)))
	}()

	log.Println("starting TLS listener on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", protectedHandler))
}
```

## Explanation
The fix replaces the unprotected `mux` with a dedicated `redirectToHTTPS` handler that redirects all HTTP requests to HTTPS. This ensures that all state-changing requests (including POST /settings) are routed through the TLS listener where CSRF protection is applied via `protectedHandler`. The redirect is permanent (HTTP 301) to encourage clients to use HTTPS.

The root cause was that the plaintext listener was inadvertently serving the entire application instead of only performing an HTTP-to-HTTPS redirect. By creating a minimal redirect handler, we prevent any requests from bypassing CSRF protection.
