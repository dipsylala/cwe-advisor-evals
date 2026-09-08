## Verdict

Confirmed. CWE-352 (Cross-Site Request Forgery) - exploitable as reported.

## Source

Any cross-origin browser request reaching the plaintext listener on `:8080`. Since that listener serves the full application `mux` (not `protectedHandler`), an attacker page can submit a same-site-cookie-carrying request to `http://<host>:8080/settings` and it will be dispatched exactly like a legitimate request.

## Fix

### File: main.go

```go
package main

import (
	"log"
	"net"
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

// httpsRedirectHandler sends every plaintext request to the TLS
// listener instead of serving application routes over an unprotected
// connection.
func httpsRedirectHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	target := "https://" + host + ":8443" + r.URL.RequestURI()
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
	// to https://. It carries its own redirect-only handler so it can
	// never serve the application mux - settings update included -
	// without CSRF protection.
	go func() {
		log.Println("starting plaintext listener on :8080")
		log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(httpsRedirectHandler)))
	}()

	log.Println("starting TLS listener on :8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", protectedHandler))
}
```

## Explanation

The plaintext `:8080` listener was passed `mux` directly, so it served every route - including `POST /settings` - with none of the `http.CrossOriginProtection` wrapping that `protectedHandler` provides on the TLS listener. That let a forged cross-origin request reach `updateSettingsHandler` over plain HTTP, bypassing CSRF protection entirely regardless of how well-configured the TLS-side protection was, since CSRF protection can only be effective if every path to a state-changing handler goes through it.

The fix removes `mux` from the `:8080` listener entirely and replaces it with a dedicated `httpsRedirectHandler` that only issues a 301 redirect to the HTTPS equivalent URL on `:8443`. The plaintext port no longer has any route capable of reaching `updateSettingsHandler`, `viewSettingsHandler`, or any other application handler, so the only way to reach state-changing functionality is through `protectedHandler`, where `CrossOriginProtection` enforces Fetch-metadata-based origin checks before the request reaches `svc`. No CSRF token or middleware library work was needed here because the protection mechanism (`http.NewCrossOriginProtection`) was already correctly constructed and configured (`AddTrustedOrigin`) - the defect was purely that a second, unprotected path to the same handlers existed. `buildMux` and `SettingsService` are unchanged since the routing and business logic were never the problem; only which handler backs the plaintext listener changed.

Checked: `go build ./...` and `go vet ./...` against the fixed file plus the unmodified `settings_service.go`, in a scratch module - both completed with no errors or diagnostics. `net.SplitHostPort` and `http.Redirect` are standard-library (`net`, `net/http`); `http.HandlerFunc` and `http.StatusMovedPermanently` were already available via the existing `net/http` import.

## Behaviour changes

- Any client that was reaching the application (including legitimate GET requests to `/healthz` or `/settings`) over plain `http://<host>:8080/...` now receives a `301 Moved Permanently` redirect to `https://<host>:8443/...` instead of a direct response. This matches the code's own stated intent ("a plaintext listener that exists only to bounce http:// visitors to https://") and is not a new restriction - it completes a behaviour the comment already claimed was in place.
- No change to the TLS listener, to `buildMux`, to `SettingsService`, or to any route's method or path.
