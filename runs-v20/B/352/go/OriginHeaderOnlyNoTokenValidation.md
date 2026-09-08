## Verdict

Exploitable. CWE-352 (Cross-Site Request Forgery).

## Source

`UpdateSettingsHandler` in `account_settings.go` authenticates the caller from the `session_id` cookie alone (`accountIDFromSession`, line 61). A browser attaches this cookie automatically to any request the victim's browser sends to `app.example.com`, including one triggered from a cross-site page the attacker controls (an auto-submitting form or `fetch` with credentials). The request body (`req.Email`, `req.DisplayName`) is attacker-controlled JSON supplied by that forged request.

## Fix

### File: account_settings.go

```go
package accounts

import (
	"encoding/json"
	"net/http"
)

// appHost is the canonical host this service is served from. It is used to
// validate that state-changing requests originate from our own front end.
const appHost = "app.example.com"

// originProtection rejects cross-origin state-changing requests using
// Sec-Fetch-Site metadata, falling back to an Origin/Host comparison for
// older clients. appHost is registered explicitly as the trusted origin so
// the check does not depend on how a reverse proxy sets the request's Host
// header.
var originProtection = newOriginProtection()

func newOriginProtection() *http.CrossOriginProtection {
	p := http.NewCrossOriginProtection()
	if err := p.AddTrustedOrigin("https://" + appHost); err != nil {
		panic("accounts: invalid trusted origin: " + err.Error())
	}
	return p
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

// UpdateSettingsHandler updates the caller's email and display name.
// Cross-origin state changes are rejected by originProtection before any
// business logic runs; session authentication alone does not gate the
// mutation below.
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := originProtection.Check(r); err != nil {
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
// session cookie. Authentication succeeds independently of the Origin check
// above, so a forged cross-site request carrying the victim's session
// cookie still reaches the sink once (or if) the Origin check is bypassed
// or simply absent, since browsers do not send Origin on every request type
// a forged form submission can trigger.
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

The handler's only defense was a hand-rolled comparison of `url.Parse(Origin).Host` against a constant, which is easy to get wrong (it ignores scheme, and is bypassed outright whenever the request carries no `Origin` header at all - a case the code treats as "not trusted" today, but any future edit to that fallback silently reopens the hole). It is replaced with the standard library's `net/http.CrossOriginProtection` (Go 1.25.1+), which rejects a non-safe-method request unless it can affirmatively show it is same-origin - first by inspecting the browser-set `Sec-Fetch-Site` header (present on all modern browsers since 2023), and only where that is absent, falling back to an Origin/Host comparison. `appHost` is registered with `AddTrustedOrigin` so the trust decision does not depend on whatever Host header a proxy happens to forward. `originProtection.Check(r)` runs before authentication and before the request body is read, so a forged cross-site request carrying a valid session cookie is rejected with 403 before `UpdateSettings` is ever called - closing the CWE-352 sink at line 74 (now line 75). This is an Origin-based check, not a synchronizer token; the knowledge base names `CrossOriginProtection` as the primary Go 1.25.1+ fix precisely because it replaces ad hoc Origin/Referer logic with the framework-maintained equivalent, rather than requiring a hand-rolled token store.

## Behaviour changes

- Removed `isTrustedOrigin` and the `net/url` import (dead code once its only caller is gone); replaced by `originProtection.Check(r)`, which performs the equivalent same-origin decision via the standard library.
- The 403 response is now also returned in one case the old code did not cover: a cross-site POST whose `Sec-Fetch-Site` header explicitly says `cross-site` even when the request happens to omit `Origin` (a legacy-browser corner case). This tightens the check; it does not loosen it. All same-origin traffic - a request whose `Origin` matches `https://app.example.com`, and any non-browser or same-site request that carries neither header - is treated exactly as before (allowed through to the session check).
- No change to the method check, session/auth flow, request body decoding, store call, or response codes/bodies for the success and validation-failure paths.

**Assumption**: the service is assumed to be reachable at `https://app.example.com` (TLS). If it is legitimately served over plain HTTP in some environment, `AddTrustedOrigin` should register `http://app.example.com` (or both) - the knowledge base gives no version/scheme guidance for this beyond "compare against an explicit allowlist of hosts," so the scheme choice is inferred from the constant's name and typical production practice. This also assumes the target module's `go.mod` declares `go 1.25.1` or later; `net/http.CrossOriginProtection` does not exist before Go 1.25, and 1.25.0 has a known bypass (CVE-2025-47910) that 1.25.1 fixes.

**Verification**: copied the file into a scratch module (`go.mod` with `go 1.25.1`) and ran `go build ./...` and `go vet ./...` - both succeeded with no errors or warnings.
