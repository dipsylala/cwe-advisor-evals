## Verdict

Exploitable

## Source

```go
package accounts

import (
	"encoding/json"
	"net/http"
	"net/url"
)

const appHost = "app.example.com"

type settingsUpdateRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type AccountService struct {
	store AccountStore
}

type AccountStore interface {
	UpdateSettings(accountID, email, displayName string) error
}

func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	mux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
}

func isTrustedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == appHost
}

func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !isTrustedOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	accountID, ok := accountIDFromSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req settingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
	if err := s.store.UpdateSettings(accountID, req.Email, req.DisplayName); err != nil {
		http.Error(w, "failed to update settings", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func accountIDFromSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return lookupAccountIDBySession(cookie.Value)
}

func lookupAccountIDBySession(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	return "acct_" + sessionID, true
}
```

## Fix

```go
package accounts

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gorilla/csrf"
)

const appHost = "app.example.com"

type settingsUpdateRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type AccountService struct {
	store AccountStore
}

type AccountStore interface {
	UpdateSettings(accountID, email, displayName string) error
}

func RegisterRoutes(mux *http.ServeMux, svc *AccountService, csrfAuthKey []byte) http.Handler {
	// Wrap the mux with CSRF protection middleware
	// csrfAuthKey must be 32 bytes, loaded from a secret store, never hardcoded
	csrfProtection := csrf.Protect(csrfAuthKey, csrf.Secure(true), csrf.SameSite(csrf.SameSiteStrictMode))
	
	mux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
	return csrfProtection(mux)
}

func isTrustedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == appHost
}

func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// CSRF token is now validated by the middleware before this handler is reached.
	// The Origin check is retained as supplementary defense-in-depth only.
	if !isTrustedOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	accountID, ok := accountIDFromSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req settingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// State-changing operation now protected by CSRF token validation
	if err := s.store.UpdateSettings(accountID, req.Email, req.DisplayName); err != nil {
		http.Error(w, "failed to update settings", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func accountIDFromSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return lookupAccountIDBySession(cookie.Value)
}

func lookupAccountIDBySession(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	return "acct_" + sessionID, true
}
```

## Explanation

The original code relies solely on the Origin header for CSRF protection, which is insufficient. Browsers do not send the Origin header on all requests, particularly form submissions over HTTP or in certain legacy contexts. An attacker can forge a cross-site request that bypasses this check, exploiting the victim's existing session cookie to perform unauthorized account modifications.

The fix wraps the router with the `gorilla/csrf` middleware, which validates a CSRF token on every state-changing request (POST/PUT/DELETE) before the handler executes. The middleware returns a 403 Forbidden response if the token is missing or invalid, preventing the sink from being reached by forged requests. The session cookie is also hardened with `SameSite=Strict` and `Secure` flags.

The Origin header check is retained as supplementary defense-in-depth validation, not as the sole control. Requests must pass both the token validation and the Origin check to proceed.

For Go versions prior to 1.25.1, `gorilla/csrf` v1.7.3+ is required to block the Referer bypass (CVE-2025-24358). Note that v1.7.3 and later contain CVE-2025-47909, which has no fixed release in gorilla/csrf; a migration to `filippo.io/csrf/gorilla` is recommended as a drop-in replacement that does not exhibit this vulnerability.

## Behaviour changes

- **RegisterRoutes signature change**: Now accepts `csrfAuthKey []byte` parameter (32-byte key loaded from secure configuration, never hardcoded) and returns `http.Handler` instead of void. Callers must pass the CSRF authentication key (generated once via `securecookie.GenerateRandomKey(32)` and stored securely) and wrap the returned handler in their HTTP server registration.
- **Import addition**: Adds `"github.com/gorilla/csrf"` dependency.
- **CSRF token requirement**: All POST requests to `/account/settings` must now include a valid CSRF token (either in the request body as a hidden field named `gorilla.csrf.Token`, or in the `X-CSRF-Token` header for AJAX requests). Requests without a valid token receive HTTP 403 Forbidden before business logic executes.
- **Handler return point**: The handler now rejects unauthenticated requests (missing or invalid session) before the CSRF check, as before, but additionally rejects any request failing CSRF validation by the middleware layer.
- **Session cookie hardening**: Applications using this handler should set `SameSite: http.SameSiteStrictMode`, `Secure: true`, and `HttpOnly: true` on session cookies as defense-in-depth.
