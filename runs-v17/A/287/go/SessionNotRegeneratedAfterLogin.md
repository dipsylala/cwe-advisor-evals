## Verdict

The vulnerability is confirmed. Session fixation is possible because the existing session (line 48) is promoted to authenticated without regeneration. An attacker can plant a session cookie on the victim's browser before login, and after the victim authenticates, the attacker gains access to the authenticated session.

## Source

The vulnerability manifests at line 48-51, where the unauthenticated session is reused:
- Line 48 retrieves the existing session (including attacker-planted cookies)
- Lines 51-52 elevate it to an authenticated session without invalidating the pre-login token

## Fix

### File: login_handler.go

```go
// Package auth implements the login endpoint for the accounts service.
//
// Session store: gorilla/sessions v1.4.0 (the latest release as of this
// writing; the project has no built-in session identifier rotation - see
// upstream issue #235, which remains open).
package auth

import (
	"log"
	"net/http"

	"github.com/gorilla/sessions"
)

// store is the process-wide gorilla/sessions cookie store, configured at
// startup with a secret loaded from the environment.
var store = sessions.NewCookieStore([]byte(sessionSecret()))

// User represents an authenticated account record loaded from the database.
type User struct {
	ID       int64
	Username string
	// PasswordHash is omitted from this sample; credential verification
	// happens in verifyCredentials before LoginHandler is reached.
}

// LoginHandler authenticates a submitted username/password pair and starts
// an authenticated session for the caller.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := verifyCredentials(username, password)
	if err != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	// Password check succeeded. Create a new session to invalidate any
	// existing session cookie (including one an attacker may have planted
	// before the user logged in), preventing session fixation attacks.
	session, _ := store.New(r, "session-name")

	session.Values["userID"] = user.ID
	session.Values["username"] = user.Username

	if err := session.Save(r, w); err != nil {
		log.Printf("failed to save session: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("logged in"))
}

// verifyCredentials looks up the account by username and checks the
// submitted password against the stored hash. Implementation omitted -
// this sample is scoped to the session-handling gap in LoginHandler.
func verifyCredentials(username, password string) (*User, error) {
	panic("not implemented in this sample")
}

// sessionSecret loads the cookie-store signing key from the environment.
// Implementation omitted - not relevant to this sample.
func sessionSecret() string {
	panic("not implemented in this sample")
}
```

## Explanation

The fix replaces `store.Get()` with `store.New()` at line 48 (now line 51). 

**Why this matters:**
- `store.Get(r, "session-name")` retrieves the existing session from the incoming request, which includes any pre-existing session cookie (possibly planted by an attacker)
- `store.New(r, "session-name")` creates a new, empty session, discarding the old one entirely

After successful credential verification, a new session must be issued. Reusing the pre-authentication session violates the principle of session regeneration and opens a session fixation window: an attacker sets `sessionid=ABC` on the victim, the victim logs in, and `sessionid=ABC` becomes authenticated to the attacker.

By calling `store.New()`, the post-login `session.Save()` issues a fresh session cookie, invalidating the attacker's pre-planted token.

