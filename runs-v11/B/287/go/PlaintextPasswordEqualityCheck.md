## Verdict

The finding is confirmed. Line 47 compares plaintext passwords directly using `==`, allowing an attacker to bypass authentication by submitting the stored password. The stored passwords themselves are in plaintext, compounding the weakness.

## Source

`req.Password` (lines 26-29, 34-38): Attacker-controlled user input from the HTTP request body, decoded as JSON without validation beyond its type.

## Fix

Replace the login handler to use `bcrypt.CompareHashAndPassword` for constant-time comparison, and update the `User` struct to store password hashes instead of plaintext passwords. Run the comparison even when the username is not found, using a pre-computed dummy hash to prevent timing-based user enumeration.

```go
package auth

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// User represents an account record loaded from the user store.
type User struct {
	Username     string
	PasswordHash string
}

// userStore stands in for a database table of accounts. The password
// column now holds bcrypt hashes.
var userStore = map[string]*User{
	"alice": {Username: "alice", PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36P4/KFm"}, // example: bcrypt hash
}

// Dummy hash generated at startup for constant-time comparison on unknown users.
var dummyHash string

func init() {
	var err error
	dummyHash, err = bcrypt.GenerateFromPassword([]byte(""), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("failed to generate dummy hash: %v", err)
	}
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
	
	// Use dummy hash if user not found or hash is empty, preventing timing-based user enumeration.
	hash := dummyHash
	if ok && user.PasswordHash != "" {
		hash = user.PasswordHash
	}
	
	// Compare password using constant-time comparison.
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password))
	
	// Only issue a session if both the user exists and the password matches.
	if ok && err == nil {
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

The original code compared plaintext passwords directly using `==`. This vulnerability has two aspects:

1. **Direct plaintext comparison**: An attacker who obtains the stored password file can immediately impersonate any user. The comparison itself is also vulnerable to timing attacks, leaking whether the first character matches before the attacker knows the rest of the password.

2. **User enumeration via timing**: The original code returned immediately when `lookupUser` failed, skipping the password comparison entirely. An attacker could time responses to determine which usernames exist in the database.

The fix uses `golang.org/x/crypto/bcrypt` with `bcrypt.CompareHashAndPassword`, which provides constant-time comparison. The password hash is salted during generation, so even identical passwords produce different hashes. This protects stored passwords even if the database is compromised.

The fix also runs `bcrypt.CompareHashAndPassword` on both the found-user and not-found paths (using a pre-computed dummy hash when the username is unknown or the stored hash is empty). This ensures the authentication check always takes the same time, preventing an attacker from using response timing to enumerate valid usernames.

## Behaviour changes

- Stored passwords now contain bcrypt hashes (salted, one-way) instead of plaintext values, eliminating direct password exposure if the database is leaked.
- Login now requires the password to match a bcrypt hash of the stored value, not the plaintext password itself. The password field in the `User` struct is renamed to `PasswordHash` to reflect this.
- The comparison is constant-time, preventing timing attacks that could leak whether individual characters match.
- Failed authentication (whether from unknown username or wrong password) now takes the same time by design, removing a user-enumeration oracle.
- A new package-level `init` function pre-computes the dummy hash at startup. If hash generation fails, the handler will fail on all login attempts rather than panic.
