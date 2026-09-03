# Remediation: CWE-352 (Cross-Site Request Forgery)

## Verdict

**CONFIRMED** — The handler relies solely on the `Origin` header to validate CSRF, which is insufficient. The vulnerability allows attackers to forge cross-site state-changing requests that bypass the `isTrustedOrigin()` check.

## Source

Authenticated request from `r` carrying the victim's session cookie (`accountIDFromSession(r)` at line 61) and user-supplied JSON body (`req.Email`, `req.DisplayName` at lines 67–71). The Origin header is attacker-influenced or absent in certain browser scenarios.

## Fix

Replace the Origin-only validation with **CSRF token validation** using the Synchronizer Token Pattern. Wrap the state-changing handler with CSRF protection middleware and validate tokens server-side before processing mutations.

**Option A: Go 1.25.1+ with Standard Library** (Recommended)

Use `net/http.CrossOriginProtection` to wrap the router. This middleware rejects cross-origin state-changing requests using Fetch metadata headers:

```go
import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// Generate a 128-bit CSRF key once at startup (store securely, do not hardcode)
func generateCSRFKey() []byte {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

// RegisterRoutes wraps the mux with CrossOriginProtection middleware
func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	mux.HandleFunc("POST /account/settings", svc.UpdateSettingsHandler)
	
	// Wrap with CSRF protection (Go 1.25.1+)
	// In your main(), apply this to the server handler:
	// protectedMux := net.http.CrossOriginProtection(mux)
	// http.ListenAndServe(":8080", protectedMux)
}

// UpdateSettingsHandler now processes only requests that passed
// the CSRF check in the middleware below
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// CSRF validation now happens in the middleware, not here.
	// Remove the isTrustedOrigin() check—CrossOriginProtection handles it.

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

// In main():
// import "net/http"
// mux := http.NewServeMux()
// RegisterRoutes(mux, svc)
// protected := http.CrossOriginProtection(mux)
// http.ListenAndServe(":8080", protected)
```

**Option B: Older Go Versions with `filippo.io/csrf/gorilla`**

For Go versions before 1.25.1, use the drop-in replacement for `gorilla/csrf` that does not suffer from CVE-2025-47909:

```go
import "filippo.io/csrf/gorilla"

func RegisterRoutes(mux *http.ServeMux, svc *AccountService, csrfKey []byte) {
	mux.HandleFunc("POST /account/settings", svc.UpdateSettingsHandler)
	
	// Wrap the mux with CSRF middleware
	// In main(), apply the protected mux to the server:
	// protected := csrf.Protect(csrfKey, 
	//     csrf.Secure(true), 
	//     csrf.SameSite(csrf.SameSiteStrictMode))(mux)
	// http.ListenAndServe(":8080", protected)
}

func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	// Remove isTrustedOrigin() check—the CSRF middleware validates now
	
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
```

**Key changes in both options:**

1. **Remove `isTrustedOrigin()` call** — The Origin header check is replaced by server-enforced CSRF validation (Fetch metadata or token-based).
2. **Wrap the router** — CSRF middleware intercepts all requests and rejects forged state-changing calls before handlers run.
3. **Session cookie hardening** — Set `SameSite=Strict`, `Secure=true`, and `HttpOnly=true` on the session cookie in `accountIDFromSession()`:

```go
// Update cookie issuance elsewhere in your code:
cookie := &http.Cookie{
	Name:     "session_id",
	Value:    sessionID,
	Path:     "/",
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteStrictMode,
	MaxAge:   3600,
}
http.SetCookie(w, cookie)
```

## Explanation

The Origin header is a browser hint that cannot be trusted as the sole CSRF defence because:

- Browsers do not send `Origin` on every request type (e.g., certain form submissions or cross-origin navigations).
- The header can be absent in some client contexts (non-browser clients, proxies).
- Relying on a single header leaves the application vulnerable to bypass scenarios.

**The fix uses Fetch metadata (standard library) or cryptographic tokens (filippo.io/csrf/gorilla)** to enforce that state-changing requests originate from the same origin and carry valid proof of intent. The middleware validates this proof *before* the handler executes, ensuring `UpdateSettings()` never processes forged requests. Removing the `isTrustedOrigin()` call eliminates the false sense of security from the Origin-only check and makes the real validation transparent to the handler logic.

The `SameSite` cookie attribute adds defense-in-depth: even if the CSRF token validation is misconfigured, the `Strict` mode prevents the session cookie from being sent on cross-site requests.

## Behaviour changes

1. **Token validation is mandatory** — State-changing requests now require either:
   - A valid Fetch metadata header (`Sec-Fetch-Site: same-origin`) when using `net/http.CrossOriginProtection`, or
   - A valid server-signed CSRF token in the request body or header when using `filippo.io/csrf/gorilla`.

2. **Requests lacking valid credentials are rejected with HTTP 403** — Cross-origin form submissions, AJAX calls, or requests missing the token now receive `Forbidden` before any business logic runs.

3. **Session cookie no longer relies on `Origin` header presence** — The security guarantee is now enforced by the middleware, not delegated to optional browser behavior.

4. **Pre-flight requests are blocked** — Cross-origin preflight requests to POST handlers are rejected by the middleware; legitimate cross-origin clients must be updated to include CSRF tokens or credentials (if using `filippo.io/csrf/gorilla`).
