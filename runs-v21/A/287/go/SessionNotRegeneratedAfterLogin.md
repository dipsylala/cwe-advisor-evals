## Verdict
CONFIRMED - Session fixation vulnerability. The code reuses an existing session (which an attacker may have pre-set on the victim's browser) after authentication rather than regenerating a new session identifier. This allows an attacker to hijack authenticated sessions.

## Source
File: login_handler.go, lines 44-52

The vulnerable pattern is calling `store.Get(r, "session-name")` to retrieve an existing session and then promoting it to an authenticated session by storing user credentials in it. An attacker can pre-set a session ID on a victim's browser (e.g., via a malicious link), then after the victim logs in, that same session ID carries the authenticated payload.

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

	// Invalidate any pre-existing session to prevent session fixation attacks.
	// An unauthenticated session (set by an attacker or legitimately from a
	// previous anonymous browsing session) must not be carried over into an
	// authenticated context with the same identifier.
	oldSession, _ := store.Get(r, "session-name")
	if oldSession != nil {
		oldSession.Options.MaxAge = -1
		oldSession.Save(r, w)
	}

	// Create a fresh session after successful authentication.
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
The vulnerability arises from session fixation: after successful credential verification, the code must discard any pre-existing session and issue a new one to the client. By reusing `store.Get()`, the old session identifier (which an attacker may have planted) becomes associated with the authenticated user.

The fix:
1. Retrieve the old session and mark it for deletion by setting `MaxAge = -1`, then save it to send a cache-busting Set-Cookie header to the client
2. Create a fresh session using `store.New()` instead of `store.Get()`
3. Store user credentials in the new session

This ensures that only a newly-issued session identifier can carry authenticated state, breaking the attacker's fixation attack. The client's browser receives both a Set-Cookie clearing the old session and a new cookie with a fresh, server-issued identifier.
