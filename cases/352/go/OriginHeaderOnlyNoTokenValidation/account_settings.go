package accounts

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// appHost is the canonical host this service is served from. It is used to
// validate that state-changing requests originate from our own front end.
const appHost = "app.example.com"

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
// This is the only check the handler below performs before mutating state.
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
