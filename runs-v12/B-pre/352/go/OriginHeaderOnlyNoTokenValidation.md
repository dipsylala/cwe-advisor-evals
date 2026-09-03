## Verdict

Confirmed CWE-352: Cross-Site Request Forgery. The handler at line 74 performs state-changing operations (POST to `/account/settings`) while relying solely on an Origin header check for CSRF protection. This is insufficient because browsers do not always send the Origin header, and an attacker can craft cross-site requests carrying the victim's session cookie that bypass or omit the header. The handler lacks proper CSRF token validation required by the Synchronizer Token Pattern.

## Source

File: `account_settings.go`

**Vulnerable chain**:
- Line 56: `isTrustedOrigin(r.Header.Get("Origin"))` - validates only the Origin header
- Line 74: `s.store.UpdateSettings(accountID, req.Email, req.DisplayName)` - performs state mutation without CSRF token

**Sink**: The `UpdateSettings` call at line 74 mutates persistent state (account settings) without verifying a server-controlled CSRF token.

**Data flow**: HTTP POST request → Origin header validation (insufficient) → Session retrieval (via cookie) → JSON body decode → State mutation

## Fix

Apply `net/http.CrossOriginProtection` (requires Go 1.25.1+) to wrap the router. This enforces same-origin policy for state-changing requests using Fetch metadata headers, eliminating the Origin-only reliance:

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

// RegisterRoutes wraps the handler with CrossOriginProtection middleware
// to enforce same-origin CSRF validation on state-changing requests.
func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
	
	// Wrap with CrossOriginProtection to validate state-changing requests
	mux.Handle("/account/", http.CrossOriginProtection(protectedMux))
}

// UpdateSettingsHandler updates the caller's email and display name.
// CSRF protection is enforced by the CrossOriginProtection middleware
// wrapping this handler, which validates Sec-Fetch-Site and Sec-Fetch-Mode
// headers to ensure the request originated from same-origin.
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

**Key changes**:
1. Removed `isTrustedOrigin()` function - the Origin header check is replaced by `CrossOriginProtection` middleware
2. Wrapped the protected mux with `http.CrossOriginProtection()` in `RegisterRoutes` - this enforces Fetch metadata validation on all state-changing requests (POST/PUT/DELETE) matching the pattern
3. Removed the `isTrustedOrigin(r.Header.Get("Origin"))` check from the handler - it is now enforced at the middleware level
4. Updated handler documentation to reflect that CSRF protection is middleware-driven

**For Go versions older than 1.25.1**, use `filippo.io/csrf/gorilla` as a drop-in replacement (API-compatible with `gorilla/csrf` but using the same Fetch-metadata strategy):

```go
import "filippo.io/csrf"

func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
	
	// csrf.Protect requires a 32-byte key loaded from secure config
	csrfKey := []byte{} // Load from secure config, not hardcoded
	csrfMiddleware := csrf.Protect(
		csrfKey,
		csrf.Secure(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
	)
	mux.Handle("/account/", csrfMiddleware(protectedMux))
}
```

## Explanation

The original code relied solely on validating the `Origin` header, which is insufficient for CSRF protection because:
1. Browsers do not always send the Origin header (e.g., form submissions from older user agents, same-origin redirects)
2. Even when present, the Origin can be manipulated or spoofed in certain attack scenarios
3. An attacker can craft a forged cross-site request that carries the victim's session cookie and performs unwanted state changes

`net/http.CrossOriginProtection` (Go 1.25.1+) enforces the Synchronizer Cross-Origin-Policy by validating Fetch metadata headers (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`) that browsers send automatically on state-changing requests. These headers cannot be spoofed by an attacker's JavaScript running in a different origin, providing cryptographically-strong CSRF protection without requiring manual token management.

The fix eliminates the weak Origin header check and replaces it with browser-enforced same-origin validation. For older Go versions, `filippo.io/csrf/gorilla` provides the same protection strategy using the drop-in middleware pattern.

## Behaviour changes

**For legitimate users**:
- State-changing requests (POST to `/account/settings`) from the same origin continue to work without modification
- No token generation, submission, or validation is required in forms or AJAX requests—the browser's Fetch metadata headers handle it automatically
- Response behavior is unchanged: successful updates return 204 No Content, errors return appropriate status codes

**For forged cross-site requests**:
- Requests originating from a different domain are rejected by the `CrossOriginProtection` middleware with HTTP 403 Forbidden before reaching the handler
- The handler never executes, so no state mutation occurs
- This blocks the attack vector where a victim's session cookie is used to forge cross-site requests

**Configuration requirement**:
- The handler must be registered within the `CrossOriginProtection`-wrapped router to receive protection
- Handlers registered on separate `http.ServeMux` instances or outside the protected middleware are not defended
- Session cookies should also set `SameSite=Strict` or `Lax` and `HttpOnly=true` as defense-in-depth (not shown in the fix, but recommended in the Go CWE-352 guidance)
