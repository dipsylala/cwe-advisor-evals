## Verdict

CONFIRMED. The finding is a real vulnerability: an attacker can plant a session cookie before the user logs in, and the authenticated session will retain the attacker's injected values alongside the authenticated user data, allowing the attacker to access the authenticated session.

## Source

The vulnerability is in the `LoginHandler` function, lines 48-52 of `login_handler.go`:

```go
session, _ := store.Get(r, "session-name")

session.Values["userID"] = user.ID
session.Values["username"] = user.Username
```

The `store.Get(r, "session-name")` call decodes the session cookie from the request, which may have been planted by an attacker before the user logged in. The code then adds authenticated user data to this existing session object without clearing the attacker-controlled values.

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

	// Retrieve the session cookie, which may contain attacker-planted values.
	session, _ := store.Get(r, "session-name")

	// Replace session.Values wholesale with only authenticated user data,
	// discarding any attacker-controlled values that may have been in the
	// cookie before login.
	session.Values = make(map[interface{}]interface{})
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

The fix replaces `session.Values` with a newly allocated map containing only the authenticated user data. This follows the CWE-287 Go guidance: "With `CookieStore` there is no server-side identifier at all - the cookie is the session - so replace `session.Values` wholesale rather than adding the authenticated user to values decoded from the planted cookie."

By creating a fresh map and populating it only with `userID` and `username`, the fix ensures that any values an attacker planted in the cookie before login are discarded. When the session is saved, the cookie will contain only the application-controlled authenticated user data, preventing the attacker from accessing the authenticated session.

The change is minimal and surgical: only line 51 is modified to replace the assignment with a map initialization followed by populating the required fields. The rest of the flow remains unchanged.

## Behaviour changes

- **Before the fix**: An attacker-planted cookie with arbitrary session values was decoded by `store.Get()` and retained in the authenticated session alongside the user data.
- **After the fix**: The session cookie contains only the authenticated user data (`userID` and `username`), with any pre-login attacker-controlled values discarded.

This prevents session fixation attacks where an attacker pre-plants a cookie and leverages it to access the authenticated session after the victim logs in.
