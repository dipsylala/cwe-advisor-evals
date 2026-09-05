## Verdict

Exploitable. The handler performs state-changing operations (POST to `/account/settings`) using only an Origin header check for CSRF protection. This is insufficient because browsers do not send the Origin header in all cross-origin request scenarios, and the check can be bypassed. An attacker can forge a cross-site request that carries the victim's session cookie and modifies account settings without a server-controlled CSRF token.

## Source

Attacker-controlled Origin header and cross-origin POST request to `/account/settings` endpoint.

## Fix

**Vulnerable Code (lines 28-30, 50-80):**

```go
// RegisterRoutes wires the account settings handler into the application mux.
func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	mux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
}

// UpdateSettingsHandler updates the caller's email and display name.
// It relies solely on the Origin header to decide whether the request is
// legitimate; there is no CSRF synchronizer token issued, stored, or
// checked anywhere in this flow.
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

	// VULNERABLE: State-changing operation without CSRF token validation
	if err := s.store.UpdateSettings(accountID, req.Email, req.DisplayName); err != nil {
		http.Error(w, "failed to update settings", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

**Fixed Code (Go 1.25.1+):**

Wrap the router with `http.CrossOriginProtection` middleware at the top-level entry point:

```go
import (
	"encoding/json"
	"net/http"
	"net/url"
)

// No changes needed to handler logic when using CrossOriginProtection middleware
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Remove Origin header check; CrossOriginProtection validates cross-origin semantics
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

	if err := s.store.UpdateSettings(accountID, req.Email, req.DisplayName); err != nil {
		http.Error(w, "failed to update settings", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// In your main() or application setup, wrap the mux:
func main() {
	mux := http.NewServeMux()
	svc := &AccountService{store: /* your store */}
	RegisterRoutes(mux, svc)

	// Apply CrossOriginProtection middleware globally
	handler := http.CrossOriginProtection(mux)

	http.ListenAndServe(":8080", handler)
}
```

**For older Go versions (< 1.25.1):**

Use `filippo.io/csrf/gorilla` middleware (the maintained replacement for `gorilla/csrf` that avoids CVE-2025-47909):

```go
import (
	"filippo.io/csrf"
)

func main() {
	mux := http.NewServeMux()
	svc := &AccountService{store: /* your store */}
	RegisterRoutes(mux, svc)

	// authKey must be 32 bytes loaded from secure config, generated once with:
	// securecookie.GenerateRandomKey(32)
	authKey := []byte("your-32-byte-auth-key-from-config")

	handler := csrf.Protect(authKey,
		csrf.Secure(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
	)(mux)

	http.ListenAndServe(":8080", handler)
}
```

Additionally, harden session cookies:

```go
// In accountIDFromSession or cookie creation:
cookie := &http.Cookie{
	Name:     "session_id",
	Value:    sessionValue,
	Path:     "/",
	SameSite: http.SameSiteStrictMode,
	Secure:   true,
	HttpOnly: true,
	MaxAge:   3600,
}
http.SetCookie(w, cookie)
```

## Explanation

The original code relied solely on an Origin header check (`isTrustedOrigin()`) to prevent CSRF attacks. This approach is insufficient because:

1. **Browsers do not always send Origin**: Some cross-origin requests, particularly simple requests and certain form submissions, may not include an Origin header, allowing the request to bypass the check.
2. **Origin validation alone is not CSRF protection**: CWE-352 requires server-controlled, cryptographically-sound validation mechanisms (CSRF tokens), not just header inspection.
3. **Susceptible to browser behavior changes**: Relying on browser-sent headers creates a dependency on browser behavior that is outside the developer's control.

The fix uses `http.CrossOriginProtection` (Go 1.25.1+), which implements the standard Fetch metadata-based CSRF protection by:
- Rejecting cross-origin requests automatically before the handler runs
- Using more robust signals (Fetch metadata headers) that cannot be spoofed by browser-based attacks
- Validating the same-origin semantics of the request through standards-compliant mechanisms

For older Go versions, `filippo.io/csrf/gorilla` provides equivalent protection while avoiding the CVE-2025-47909 vulnerability present in `gorilla/csrf` v1.7.3+.

The session cookie hardening with `SameSite=Strict`, `Secure=true`, and `HttpOnly=true` provides defense-in-depth by preventing the browser from automatically including the session cookie in cross-origin requests (where `SameSite=Strict` applies).

## Behaviour changes

The `isTrustedOrigin()` function check is removed from the handler because `CrossOriginProtection` (or `csrf.Protect`) middleware rejects cross-origin state-changing requests before the handler is invoked. This eliminates redundant validation and ensures consistent CSRF protection across all routes registered under the protected router. The handler's business logic (`UpdateSettings` sink) remains unchanged; only the preceding origin validation is replaced with middleware-based CSRF protection. Session cookies now include `SameSite=Strict`, `Secure=true`, and `HttpOnly=true` flags, which prevents the browser from automatically sending the cookie in cross-origin requests as an additional defense layer.
