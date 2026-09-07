# CWE-352 Remediation: OriginHeaderOnlyNoTokenValidation

## Verdict

**Exploitable**: The handler processes state-changing requests (POST to `/account/settings`) while relying solely on the `Origin` header for CSRF protection. This is insufficient because:
- Not all request types include the `Origin` header (simple POST requests may not)
- The `Origin` header is browser-enforced and absent from non-browser clients
- Per CWE-352 guidance: "Never rely on Origin/Referer presence alone"
- The lack of a synchronizer-token or Fetch-metadata validation mechanism leaves the state-changing sink exploitable to CSRF attacks

## Source

Request metadata: `Origin` header value (line 56: `r.Header.Get("Origin")`) and implicit request properties (Fetch metadata headers like `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`)

## Fix

### File: account_settings.go

```go
package accounts

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// appHost is the canonical host this service is served from. It is used as
// a defense-in-depth supplementary check for state-changing requests.
const appHost = "app.example.com"

// crossOriginProtection enforces CSRF protection using Fetch metadata headers.
// It must be a package-level variable so it is initialized once and reused across requests.
var crossOriginProtection *http.CrossOriginProtection

// init initializes the CSRF protection once at module load.
func init() {
	crossOriginProtection = &http.CrossOriginProtection{}
}

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

// isTrustedOrigin reports whether the Origin header names our own host.
// This serves as a defense-in-depth supplementary check, but is not the
// primary CSRF protection mechanism (see CrossOriginProtection.Check below).
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

// UpdateSettingsHandler updates the caller's email and display name.
// It enforces CSRF protection using net/http.CrossOriginProtection (Go 1.25.1+),
// which validates the request using Fetch metadata headers (Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest)
// to block cross-origin state-changing requests. This replaces relying solely on the Origin header.
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// PRIMARY CSRF CHECK: Validate using Fetch metadata headers.
	// CrossOriginProtection.Check() returns an error if the request appears
	// to be a cross-origin state-changing request that lacks proper origin control.
	if err := crossOriginProtection.Check(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// SECONDARY DEFENSE: Validate Origin header as supplementary check (defense-in-depth).
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

// accountIDFromSession resolves the authenticated account from the request's
// session cookie. Authentication succeeds independently of CSRF checks above,
// so a forged cross-site request carrying the victim's session cookie must be
// blocked by the CSRF protection before reaching this point.
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

The fixed handler adds primary CSRF protection using `net/http.CrossOriginProtection`, which is the standard library's built-in Fetch metadata validation available in Go 1.25.1+. This mechanism validates Fetch metadata headers (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`) that browsers automatically attach to requests, making CSRF attacks observable and blockable. The handler initializes a package-level `*http.CrossOriginProtection` once in the `init()` function and calls `Check(r)` before processing any state change. If the check fails (indicating a cross-origin request), the handler returns `http.StatusForbidden` immediately, preventing the malicious request from reaching the sink. The existing `Origin` header check is retained as a supplementary defense-in-depth mechanism but is no longer the sole barrier. This two-layer approach (Fetch metadata + Origin validation) provides robust protection against CSRF attacks while maintaining compatibility with legitimate browser requests.

## Behaviour changes

1. **Added package-level variable `crossOriginProtection`** and `init()` function: These initialize the Fetch metadata validator once at module load. Reason: The standard library's `CrossOriginProtection` must be instantiated and reused across requests to function correctly.

2. **Added `crossOriginProtection.Check(r)` call** (lines 71-74 in fixed code): This is the primary CSRF check. Reason: It validates Fetch metadata headers to reject cross-origin state-changing requests, closing the CSRF vulnerability that relying on `Origin` alone could not prevent.

3. **Reordered checks** in `UpdateSettingsHandler`: `CrossOriginProtection.Check()` now runs before the supplementary `Origin` header validation. Reason: The primary defense should execute first; if it fails, the handler returns without evaluating downstream checks.

4. **Updated comments** to clarify the two-layer CSRF protection strategy. Reason: The comments now document that the Fetch metadata check is primary and the `Origin` header validation is supplementary defense-in-depth, preventing future maintainers from treating either check as sufficient in isolation.

No changes to method signatures, return types, error handling paths, or the AccountStore interface contract. The handler still returns the same HTTP status codes and behaves identically for legitimate requests.
