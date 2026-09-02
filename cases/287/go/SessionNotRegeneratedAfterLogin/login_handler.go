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
	// browser before they logged in) is now promoted to an authenticated
	// session rather than being replaced with a freshly issued one.
	session, _ := store.Get(r, "session-name")

	// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
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
