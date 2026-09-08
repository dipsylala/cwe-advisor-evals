## Verdict

CONFIRMED CWE-352: The handler relies solely on Origin header validation without implementing a proper CSRF protection mechanism. Origin header validation alone can be bypassed, and browsers do not send the Origin header on all state-changing request types that a forged form submission can trigger. The finding is at line 74 where state mutation occurs unprotected.

## Source

The vulnerable code flow:
1. Line 56: Weak Origin header check via `isTrustedOrigin(r.Header.Get("Origin"))`
2. Line 74: State mutation via `s.store.UpdateSettings()` proceeds if the Origin check passes

The `isTrustedOrigin()` function (lines 35-44) validates only the Origin header's host portion, which is insufficient because:
- The Origin header may be absent from legitimate requests (not sent by all browsers on all request types)
- The Origin header can be spoofed in scenarios where browser protections are bypassed
- No CSRF token is issued, stored, or validated anywhere in the flow

This matches the CWE-352 pattern described in the knowledge base: relying solely on Origin/Referer presence rather than server-controlled token validation.

## Fix

Replace the entire contents of `account_settings.go` with:

### File: account_settings.go

```go
package accounts

import (
	"encoding/json"
	"net/http"
)

// csrfProtection validates Fetch metadata headers to prevent CSRF attacks.
var csrfProtection = &http.CrossOriginProtection{}

type settingsUpdateRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// AccountService applies validated settings changes to the persistence layer.
type AccountService struct {
	store AccountStore
}

// AccountStore is the persistence interface for account records.
type AccountStore interface {
	UpdateSettings(accountID, email, displayName string) error
}

// RegisterRoutes wires the account settings handler into the application mux.
func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	mux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
}

// UpdateSettingsHandler updates the caller's email and display name.
// CSRF protection is enforced via net/http.CrossOriginProtection, which
// validates Fetch metadata headers (Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest).
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate CSRF protection using Fetch metadata headers (Go 1.25.1+).
	// This check rejects cross-origin state-changing requests before any mutation occurs.
	if err := csrfProtection.Check(r); err != nil {
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

	if err := s.store.UpdateSettings(accountID, req.Email, req.DisplayName); err != nil {
		http.Error(w, "failed to update settings", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// accountIDFromSession resolves the authenticated account from the request's
// session cookie.
func accountIDFromSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return lookupAccountIDBySession(cookie.Value)
}

func lookupAccountIDBySession(sessionID string) (string, bool) {
	// Placeholder for the real session store lookup.
	if sessionID == "" {
		return "", false
	}
	return "acct_" + sessionID, true
}
```

## Explanation

The fix replaces the weak Origin-only check with Go's built-in `net/http.CrossOriginProtection` mechanism, which implements CSRF protection via Fetch metadata headers:

1. **Removed the weak `isTrustedOrigin()` function** (lines 35-44) which only validated the Origin header's host. Origin header validation alone is insufficient and documented in the CWE-352 knowledge base as a pattern that should never be the sole control.

2. **Added a package-level `csrfProtection` variable** (line 8) initialized as `&http.CrossOriginProtection{}`. This object validates Fetch metadata headers (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`) which are sent by modern browsers on all requests and cannot be spoofed by attacker-controlled JavaScript.

3. **Replaced the Origin check at line 56 with `csrfProtection.Check(r)`** (line 48 in the fixed version). This validates that:
   - The request originates from the same site (Sec-Fetch-Site: same-origin or same-site)
   - Or the request is a navigation (GET/HEAD with no body)
   - Cross-origin requests that attempt to mutate state are rejected with a non-nil error, triggering the 403 Forbidden response

4. **Preserved all other security checks**: session validation (lines 50-52), method validation (lines 42-45), and request body parsing (lines 54-56).

This approach aligns with the CWE-352 Go guidance: "Wrap state-changing routes with `net/http.CrossOriginProtection` (Go 1.25.1+)" and "Never rely on `Origin`/`Referer` presence alone."

## Behaviour changes

- **Requests validated differently**: Instead of parsing and comparing the Origin header host, the handler now validates Fetch metadata headers which are more reliable and cannot be set by attacker-controlled JavaScript in browsers.
- **Cross-origin requests rejected earlier**: The CSRF check occurs before session resolution (line 48 vs. old line 56), rejecting forged requests sooner in the request pipeline.
- **Fetch metadata headers required**: Clients that do not send Fetch metadata headers (older browsers, some REST clients) will fail the CSRF check. Modern browsers send these headers on all requests. Custom API clients must include `Sec-Fetch-Site: same-origin` or implement the same-origin check in their request logic.
- **No Origin header parsing needed**: The removed `isTrustedOrigin()` function and its `url.Parse` call are eliminated, reducing complexity and removing a potential parsing edge case.
- **Go 1.25.1+ requirement**: The fix requires Go 1.25.1 or later for `net/http.CrossOriginProtection`. Older versions require using `filippo.io/csrf/gorilla` instead.
