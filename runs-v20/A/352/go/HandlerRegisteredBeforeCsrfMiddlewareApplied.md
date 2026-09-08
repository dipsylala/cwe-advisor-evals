## Verdict

Confirmed. The plaintext listener on `:8080` is started with `mux`, the raw, unprotected `*http.ServeMux`, instead of `protectedHandler`, the `http.NewCrossOriginProtection()`-wrapped handler used on the TLS listener. Because `mux` registers `POST /settings` alongside the other routes, any client that reaches port 8080 can submit that state-changing request with no CSRF check at all - `protection.Handler()` never runs for that listener.

## Source

`E:/Github/cwe-advisor/evals/cases/352/go/HandlerRegisteredBeforeCsrfMiddlewareApplied/main.go`, line 37:

```go
log.Fatal(http.ListenAndServe(":8080", mux))
```

`mux` is the same `*http.ServeMux` built by `buildMux`, which registers `POST /settings` -> `svc.updateSettingsHandler`, a state-changing action. The TLS listener two lines below correctly wraps this same mux in `protection.Handler(mux)` before serving it; the plaintext listener bypasses that wrapper entirely.

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

// redirectToHTTPS is the small redirect handler the plaintext listener
// was always meant to carry: it never touches the application mux, so
// it cannot expose an unprotected path to the state-changing routes.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func main() {
	svc := NewSettingsService()
	mux := buildMux(svc)

	// Wrap the mux with CSRF protection before the application goes live.
	protection := http.NewCrossOriginProtection()
	protection.AddTrustedOrigin("https://app.example.com")
	protectedHandler := protection.Handler(mux)

	// A plaintext listener that exists only to bounce http:// visitors
	// to https://. It now carries its own redirect handler instead of
	// reaching for the in-scope mux variable, so it can never end up
	// serving the application - settings update included - unprotected.
	go func() {
		log.Println("starting plaintext listener on :8080")
		log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(redirectToHTTPS)))
	}()

	log.Println("starting TLS listener on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", protectedHandler))
}
```

## Explanation

The plaintext listener's only intended job is to bounce `http://` visitors to `https://`; it should never serve application routes at all, protected or not. Rather than pointing it at `protectedHandler` (which would still expose the settings endpoint over plaintext HTTP, defeating the purpose of the TLS-only listener and letting CSRF-protected-but-unencrypted traffic through), the fix gives it its own minimal handler, `redirectToHTTPS`, that issues a 301 to the same host and path over HTTPS and never touches `mux` or `protectedHandler`. This removes the only code path that could reach `svc.updateSettingsHandler` without going through `protection.Handler()`. The TLS listener is unchanged and continues to serve `protectedHandler`, so `POST /settings` is only ever reachable behind `http.NewCrossOriginProtection()`'s origin check.
