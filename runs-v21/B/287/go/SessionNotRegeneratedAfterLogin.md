## Verdict

Exploitable. An attacker can pre-plant a session cookie on a victim's browser, then after the victim logs in, use the knowledge of that cookie value to impersonate the victim. The vulnerable code promotes an existing (attacker-planted) session to authenticated status without invalidating and replacing it.

## Source

`user` returned from `verifyCredentials()` after successful authentication (line 38).

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

	// Password check succeeded above. The request's existing session cookie
	// (if any - including one an attacker may have set on the victim's
	// browser before they logged in) is now invalidated and replaced with a
	// freshly issued one.

	// First, invalidate the old session (if any).
	oldSession, _ := store.Get(r, "session-name")
	oldSession.Options.MaxAge = -1
	if err := oldSession.Save(r, w); err != nil {
		log.Printf("failed to invalidate old session: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Create a fresh authenticated session.
	session, _ := store.New(r, "session-name")
	session.Values["userID"] = user.ID
	session.Values["username"] = user.Username

	// Harden the session cookie.
	session.Options.Secure = true
	session.Options.HttpOnly = true
	session.Options.SameSite = http.SameSiteLax

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

The vulnerable code retrieved an existing session with `store.Get()` and directly added authenticated user data to it. For `CookieStore` (as used here), this promotes any attacker-planted cookie to authenticated status. The fix invalidates the old session by setting `MaxAge = -1` and calling `Save()` to expire it in the browser, then creates a fresh session with `store.New()` and replaces `session.Values` wholesale with only the authenticated user's data. The session cookie is hardened with `Secure`, `HttpOnly`, and `SameSite=Lax` flags to reduce cross-site and network-level attacks. This ensures that any pre-planted session is discarded and a completely new one is issued at login.

## Behaviour changes

- Added invalidation of the old session: retrieves the existing session, sets `MaxAge = -1`, and saves it to expire the client-side cookie. This adds a `Set-Cookie` header with an expiration directive to the response.
- Changed from `store.Get()` to `store.New()` for creating the authenticated session: `store.Get()` reuses the existing decoded session, while `store.New()` creates a fresh empty session. This is the wholesale values replacement required by CookieStore.
- Added explicit hardening: sets `session.Options.Secure`, `session.Options.HttpOnly`, and `session.Options.SameSite` on the new session. These are defensive flags that reduce attack surface but do not change functional behavior for legitimate callers.
- Added error handling for the invalidation step. If invalidation fails, the handler returns `500` rather than proceeding; this is defensive but does alter error semantics from the original code which only checked the final save.

