## Verdict

Confirmed. `UpdateSettingsHandler` authenticates the caller solely via the ambient `session_id` cookie and gates the state change on an `Origin` header check (`isTrustedOrigin`). The `Origin` header is not sent by browsers on every request type that can reach this endpoint (e.g. some legacy/plugin-driven form submissions, and any client or proxy that strips or omits it), and it is not a substitute for an unguessable, per-session credential the attacker's page cannot obtain. A cross-site page that gets the victim's browser to issue a POST to `/account/settings` — with the victim's session cookie attached automatically — reaches `store.UpdateSettings` at line 74 whenever the Origin check is bypassed, absent, or simply not evaluated the way the developer assumed. There is no CSRF synchronizer token issued, stored, or validated anywhere in the flow.

## Source

The untrusted input is the incoming HTTP POST request to `/account/settings` itself. The only thing establishing the caller's identity is the `session_id` cookie, which the browser attaches automatically to same-origin *and* cross-origin requests alike — it is not proof the request was initiated by the application's own front end. Because no unpredictable, session-bound value is required in the request and checked server-side, a forged cross-site request carrying nothing but the victim's ambient session cookie is indistinguishable, at the sink, from a legitimate request issued by the real page.

## Fix

### File: account_settings.go
```go
package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
)

// appHost is the canonical host this service is served from. It is used to
// validate that state-changing requests originate from our own front end.
const appHost = "app.example.com"

// csrfHeaderName is the custom header the front end must echo back with the
// value obtained from CSRFTokenHandler. A cross-site attacker's form or
// fetch call cannot read this value (no CORS access to the token response)
// and cannot set an arbitrary header on a simple cross-site form submission,
// so requiring it defeats CSRF even when Origin is absent or spoofable.
const csrfHeaderName = "X-CSRF-Token"

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
	mux.HandleFunc("/account/csrf-token", svc.CSRFTokenHandler)
}

// isTrustedOrigin reports whether the Origin header names our own host. This
// remains a secondary, defense-in-depth check; it is not sufficient on its
// own because the header is absent on some request types and untrustworthy
// on others, which is why the CSRF token check below is the primary defense.
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

// csrfKey signs per-session CSRF tokens. In production this must come from a
// durable, configured secret (env var, secret manager, or the same key
// material backing the session store) so tokens stay valid across restarts
// and across instances behind a load balancer; the random fallback here only
// keeps a single-process deployment self-consistent.
var csrfKey = loadCSRFKey()

func loadCSRFKey() []byte {
	if encoded := os.Getenv("CSRF_SECRET"); encoded != "" {
		if key, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(key) >= 32 {
			return key
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("accounts: failed to generate CSRF secret: " + err.Error())
	}
	return key
}

// computeCSRFToken derives a token bound to the caller's session id via
// HMAC-SHA256. Binding to the session means the token cannot be reused
// across sessions and cannot be produced by anyone who does not already
// possess a valid session (which a cross-site attacker does not).
func computeCSRFToken(sessionID string) string {
	mac := hmac.New(sha256.New, csrfKey)
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validateCSRFToken checks a caller-supplied token against the expected
// value for their session using a constant-time comparison.
func validateCSRFToken(sessionID, token string) bool {
	if token == "" {
		return false
	}
	expected := computeCSRFToken(sessionID)
	return hmac.Equal([]byte(expected), []byte(token))
}

// CSRFTokenHandler issues the caller's per-session CSRF token. The front end
// fetches this once (same-origin, so a cross-site page cannot read the
// response) and echoes it back via csrfHeaderName on state-changing calls.
func (s *AccountService) CSRFTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID, ok := sessionIDFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		CSRFToken string `json:"csrf_token"`
	}{CSRFToken: computeCSRFToken(sessionID)})
}

// UpdateSettingsHandler updates the caller's email and display name. It
// requires a valid session, a matching per-session CSRF token supplied via
// csrfHeaderName, and (as defense in depth) a same-origin Origin header,
// before it will mutate state.
func (s *AccountService) UpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID, ok := sessionIDFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	accountID, ok := lookupAccountIDBySession(sessionID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !isTrustedOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !validateCSRFToken(sessionID, r.Header.Get(csrfHeaderName)) {
		http.Error(w, "forbidden", http.StatusForbidden)
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

// sessionIDFromRequest extracts the raw session identifier from the request's
// session cookie, without resolving it to an account.
func sessionIDFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
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

The vulnerability was that the only gate on this state-changing POST was `isTrustedOrigin`, checking a header that browsers omit on some request types and that provides no cryptographic guarantee — it is not a synchronizer token, so its presence or absence does not prove the request came from the application's own front end rather than a forged cross-site form or fetch riding on the victim's ambient session cookie.

The fix adds a synchronizer-token check as the primary defense and keeps the Origin check as a secondary, defense-in-depth layer rather than removing it:

- `CSRFTokenHandler` (`GET /account/csrf-token`) issues each authenticated session a token derived as `HMAC-SHA256(csrfKey, sessionID)`, returned only to a same-origin caller — a cross-site page cannot read the response body of a cross-origin fetch to this endpoint, so it cannot learn the token.
- `UpdateSettingsHandler` now requires the caller to echo that token back via the `X-CSRF-Token` header, verified with `validateCSRFToken` using `hmac.Equal` (constant-time comparison). A forged cross-site submission — whether a plain HTML form or a `fetch`/XHR call — cannot supply this header with the correct value: a simple form post cannot set custom headers at all, and a cross-site script cannot read the token to attach it even via `fetch`.
- Binding the token to the session id (rather than using a bare, unbound double-submit cookie) means the token is worthless outside the session that received it and cannot be planted by an attacker who does not already hold a valid session.
- `csrfKey` is loaded from a `CSRF_SECRET` environment variable in production deployments (falling back to a random per-process key only so a single instance stays internally consistent); the fix note documents that a real deployment must configure a durable, shared secret across instances rather than relying on the fallback.
- Session resolution was factored into `sessionIDFromRequest` so both the token handler and the settings handler validate the token against the same session id used for authentication, keeping the two checks consistent.

This closes the CSRF gap because the sink at `store.UpdateSettings` is now reached only when the request carries proof — the per-session HMAC token — that it was issued by code running on the application's own origin with access to a prior same-origin response, which a forged cross-site request cannot produce.
