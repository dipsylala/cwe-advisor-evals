## Verdict

Confirmed. `LoginHandler` authenticates by comparing the submitted password against `user.Password` with `==` (line 47), and `userStore` holds that field as the plaintext password the user typed at signup (line 17). Two compounding problems: the credential store keeps plaintext passwords at rest, and the comparison is a native `==` over strings, which is not constant-time and leaks timing information about how many leading bytes matched. Either an at-rest disclosure (backup, log, memory dump, insider access) or a timing side-channel against the comparison lets an attacker recover or bypass the credential.

## Source

`req.Password` in `LoginHandler` (`PlaintextPasswordEqualityCheck.go:34-38`) — attacker-controlled, decoded directly from the HTTP request body with no transformation before it reaches the comparison.

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
	Username     string
	PasswordHash []byte
}

// mustHash bcrypt-hashes a password at signup/seed time so the store never
// holds a plaintext or reversible credential.
func mustHash(password string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return hash
}

// userStore stands in for a database table of accounts. The password
// column holds a bcrypt hash, never the value the user typed at signup.
var userStore = map[string]*User{
	"alice": {Username: "alice", PasswordHash: mustHash("hunter2")},
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

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)); err != nil {
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

The fix removes plaintext password storage and the native `==` comparison in favor of `golang.org/x/crypto/bcrypt`:

- `User.Password` (plaintext) becomes `User.PasswordHash` (`[]byte`), populated via `bcrypt.GenerateFromPassword` with `bcrypt.DefaultCost`. This means even a full read of `userStore` (memory dump, backup, log) never exposes a usable credential, and the same construction point is where a real signup handler would hash the incoming password before persisting it.
- The comparison in `LoginHandler` becomes `bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password))`. bcrypt's compare is not a raw byte-for-byte `==`: it independently re-derives the hash from the candidate password and the salt embedded in the stored hash, then compares the two fixed-length hash outputs, so the check's timing does not depend on how many leading bytes of the submitted password matched the real one. This closes both the at-rest exposure and the original timing side-channel in a single change.
- Control flow is otherwise unchanged: unknown username and wrong password both still fall through to the same generic `401 invalid username or password`, so the fix does not introduce a username-enumeration oracle.
- `golang.org/x/crypto/bcrypt` is the standard, actively maintained Go bcrypt implementation (part of `golang.org/x/crypto`); pull it in via `go get golang.org/x/crypto/bcrypt` and pin the version in `go.mod` for future dependency review. bcrypt truncates input beyond 72 bytes rather than erroring, which is not a concern for typical password lengths but is worth knowing if a length-related change is made later.
