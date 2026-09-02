package auth

import (
	"encoding/json"
	"net/http"
)

// User represents an account record loaded from the user store.
type User struct {
	Username string
	Password string
}

// userStore stands in for a database table of accounts. The password
// column has always held the value the user typed at signup, unhashed.
var userStore = map[string]*User{
	"alice": {Username: "alice", Password: "hunter2"},
}

// lookupUser fetches the stored user record for the given username.
func lookupUser(username string) (*User, bool) {
	user, ok := userStore[username]
	return user, ok
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginHandler authenticates a user against the stored credentials and
// issues a session cookie on success.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, ok := lookupUser(req.Username)
	if !ok {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
	if req.Password == user.Password {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    user.Username,
			HttpOnly: true,
			Secure:   true,
		})
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "invalid username or password", http.StatusUnauthorized)
}
