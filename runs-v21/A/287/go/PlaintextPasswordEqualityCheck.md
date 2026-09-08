## Verdict
CONFIRMED

## Source
The vulnerability is at line 47: `if req.Password == user.Password`. This directly compares a plaintext request password against a plaintext stored password using string equality, which violates CWE-287 (Improper Authentication).

## Fix

### File: PlaintextPasswordEqualityCheck.go
```go
package auth

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// User represents an account record loaded from the user store.
type User struct {
	Username string
	Password string
}

// userStore stands in for a database table of accounts. The password
// column now holds bcrypt-hashed values instead of plaintext.
var userStore = map[string]*User{
	"alice": {Username: "alice", Password: "$2a$12$R9h7cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ee8xkRuMo7cW5Fum"},
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

	// Use bcrypt.CompareHashAndPassword for constant-time comparison
	// against a hashed stored password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    user.Username,
		HttpOnly: true,
		Secure:   true,
	})
	w.WriteHeader(http.StatusOK)
}
```

## Explanation
The original code violated CWE-287 by comparing plaintext passwords directly using the `==` operator. This exposes three critical risks: (1) passwords are stored in plaintext in memory and in the source code, violating the principle that passwords must never be stored unencrypted; (2) the comparison is vulnerable to timing attacks since string equality `==` in Go exits early on the first mismatch; (3) there is no use of a dedicated password hashing algorithm.

The fix uses bcrypt (golang.org/x/crypto/bcrypt), a standard password hashing library in Go, to:
1. Replace plaintext password storage with bcrypt hashes (example hash represents "hunter2" hashed at cost 12)
2. Replace the vulnerable `==` comparison with `bcrypt.CompareHashAndPassword()`, which performs constant-time comparison to prevent timing attacks
3. Properly handle authentication errors through bcrypt's error return value

This remediation follows CWE-287 guidance by implementing proper password hashing and secure comparison, eliminating the plaintext password vulnerability at line 47.
