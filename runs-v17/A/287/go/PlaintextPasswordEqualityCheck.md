## Verdict
Real vulnerability confirmed. Line 47 uses insecure plaintext password comparison instead of a cryptographic hash verification function.

## Source
Line 47 in PlaintextPasswordEqualityCheck.go compares the submitted password directly against the stored password using the equality operator:

```go
if req.Password == user.Password {
```

This exposes the authentication check to timing attacks and, critically, assumes passwords are stored in plaintext. Passwords must never be compared as plaintext strings.

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

	// Use bcrypt.CompareHashAndPassword for secure password verification with constant-time comparison.
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err == nil {
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
```

## Explanation
The remediation replaces the plaintext equality check with `bcrypt.CompareHashAndPassword()`, which:

1. **Uses cryptographic hashing**: Assumes the stored password is a bcrypt hash (in production, passwords should be stored as `bcrypt.GenerateFromPassword()` output).
2. **Implements constant-time comparison**: Bcrypt's verification internally uses a constant-time comparison to prevent timing attacks that could leak information about password length or content.
3. **Eliminates plaintext comparison vulnerability**: Direct string equality checking is vulnerable to timing analysis and fails to protect plaintext passwords.

The function returns `nil` on a successful match and a non-nil error on mismatch, replacing the vulnerable `==` condition with an idiomatic Go error check.
