## Verdict
The Origin header check alone does not provide adequate CSRF protection. Browsers omit the Origin header in certain request types (e.g., simple form submissions with GET/POST), and the header itself is not a cryptographically secure token. A state-changing endpoint must validate a synchronizer token issued and stored per session, not rely on Origin validation alone.

## Source
Line 74 updates account settings without validating a CSRF synchronizer token. The handler at lines 50-80 defends only with an Origin header check (lines 56-59), which is explicitly documented as incomplete at lines 84-87.

The vulnerability chain: an attacker-controlled site makes a cross-origin request to POST /account/settings; if the victim has a valid session_id cookie, the request succeeds because the Origin check fails only when the Origin header is absent or malformed—it does not validate a request-specific token.

## Fix

### File: account_settings.go

```go
package accounts

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
)

// appHost is the canonical host this service is served from. It is used to
// validate that state-changing requests originate from our own front end.
const appHost = "app.example.com"

// csrfTokenLength is the byte length of generated CSRF tokens.
const csrfTokenLength = 32

type settingsUpdateRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	CSRFToken   string `json:"csrf_token"`
}

// AccountService applies validated settings changes to the persistence layer.
type AccountService struct {
	store         AccountStore
	tokenStore    *CSRFTokenStore
}

// CSRFTokenStore holds issued CSRF tokens keyed by session ID.
// In production, use a session store (e.g., Redis) instead of in-memory storage.
type CSRFTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]string // sessionID -> token
}

// NewCSRFTokenStore creates a new CSRF token store.
func NewCSRFTokenStore() *CSRFTokenStore {
	return &CSRFTokenStore{
		tokens: make(map[string]string),
	}
}

// StoreToken saves a CSRF token for a session.
func (s *CSRFTokenStore) StoreToken(sessionID, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[sessionID] = token
}

// ValidateToken checks whether a token matches the stored token for a session.
func (s *CSRFTokenStore) ValidateToken(sessionID, token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored, ok := s.tokens[sessionID]
	return ok && stored == token
}

// AccountStore is the persistence interface for account records.
type AccountStore interface {
	UpdateSettings(accountID, email, displayName string) error
}

// RegisterRoutes wires the account settings handler into the application mux.
func RegisterRoutes(mux *http.ServeMux, svc *AccountService) {
	mux.HandleFunc("/account/settings", svc.UpdateSettingsHandler)
	mux.HandleFunc("/account/csrf-token", svc.GetCSRFTokenHandler)
}

// isTrustedOrigin reports whether the Origin header names our own host.
// This check is a defense-in-depth measure and must not be relied upon alone.
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

// generateToken creates a cryptographically random CSRF token.
func generateToken() (string, error) {
	b := make([]byte, csrfTokenLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GetCSRFTokenHandler returns a new CSRF token for the authenticated session.
// The client must include this token in the body of state-changing requests.
func (s *AccountService) GetCSRFTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	accountID, ok := accountIDFromSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := generateToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	// Extract session ID from cookie to store the token.
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "session cookie not found", http.StatusInternalServerError)
		return
	}

	s.tokenStore.StoreToken(cookie.Value, token)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"csrf_token": token})
}

// UpdateSettingsHandler updates the caller's email and display name.
// It validates both the Origin header (as a defense-in-depth check) and a
// cryptographically random CSRF synchronizer token before processing the request.
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

	// Validate the CSRF token before proceeding.
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "session cookie not found", http.StatusUnauthorized)
		return
	}

	if req.CSRFToken == "" || !s.tokenStore.ValidateToken(cookie.Value, req.CSRFToken) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
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
The fix implements proper CSRF protection by introducing:

1. **CSRF Token Generation**: The `generateToken()` function creates a cryptographically random token using `crypto/rand`.

2. **Token Storage**: The `CSRFTokenStore` maintains a mapping of session ID to issued token. In production, replace this with a distributed session store (Redis, etc.) to support multiple instances.

3. **Token Endpoint**: The `/account/csrf-token` handler issues a new token for authenticated clients. The client must fetch this token before making a settings update.

4. **Token Validation**: Before processing the state change at line 149 (formerly line 74), the handler now validates:
   - The CSRF token is present in the request body
   - The token matches the one stored for this session

5. **Defense in Depth**: The Origin header check is retained as an additional layer but is no longer the sole defense.

The client flow is: GET /account/csrf-token (receive token) → POST /account/settings with token in body (execute change). An attacker's cross-origin form cannot include the token because it is dynamically generated per session and unknown to the attacker's site.
