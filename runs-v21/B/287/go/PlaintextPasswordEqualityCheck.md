## Verdict

CONFIRMED - plaintext password comparison using `==` operator at line 47 is vulnerable to timing attacks and must be replaced with constant-time hash comparison.

## Source

The LoginHandler authenticates users by comparing the submitted password directly against a stored plaintext password using `==`, which is exploitable via timing attacks. An attacker can:
1. Measure response time differences to enumerate valid usernames (timing varies when user is found vs. not found)
2. Distinguish correct passwords from incorrect ones by measuring bcrypt computation time on the real password path

Additionally, passwords are stored in plaintext in the User struct, violating basic credential protection.

## Fix

Replace plaintext password storage and comparison with bcrypt hashing and constant-time comparison. The fixed code:
1. Stores password hashes instead of plaintext in the User struct
2. Uses `bcrypt.CompareHashAndPassword()` for constant-time password verification
3. Generates a dummy hash at startup and uses it for unknown users, so all authentication paths take the same time
4. Initializes the user store with hashed credentials at package initialization

### File: PlaintextPasswordEqualityCheck.go

```go
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// User represents an account record loaded from the user store.
type User struct {
	Username     string
	PasswordHash string
}

// dummyHash is a bcrypt hash of a random value, used to prevent
// timing-based user enumeration attacks by running bcrypt comparison
// even when the user is not found.
var dummyHash string

// userStore stands in for a database table of accounts.
var userStore = map[string]*User{}

func init() {
	var err error

	// Generate a dummy hash at application startup for timing attack prevention
	dummyHash, err = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("failed to generate dummy hash: %v", err))
	}

	// Initialize user store with hashed password
	aliceHash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("failed to hash password: %v", err))
	}

	userStore["alice"] = &User{
		Username:     "alice",
		PasswordHash: string(aliceHash),
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

	// Use a dummy hash for unknown users to prevent timing-based enumeration
	hash := dummyHash
	if ok {
		hash = user.PasswordHash
	}

	// Compare password against the hash with constant-time comparison
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password))
	if err != nil || !ok {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	// Set session cookie only after successful authentication
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

The original code compared passwords with `==`, which is fast for plaintext strings but leaks timing information. The fix uses `golang.org/x/crypto/bcrypt` to implement cryptographically sound authentication:

1. **Password hashing**: The User struct now stores `PasswordHash` instead of `Password`. At startup, the init() function generates bcrypt hashes for all users, representing what would be read from a persistent database.

2. **Constant-time comparison**: `bcrypt.CompareHashAndPassword()` performs constant-time comparison internally, taking approximately the same duration regardless of password correctness. This prevents an attacker from measuring response times to guess passwords.

3. **Timing attack prevention on user enumeration**: The code generates a `dummyHash` at startup. When a username is not found, the code uses the dummy hash instead of returning early. This forces `bcrypt.CompareHashAndPassword()` to run for both found and not-found users, taking equal time and preventing username enumeration via timing.

4. **Proper authentication flow**: The session cookie is only set after both conditions succeed: the user exists AND the password comparison succeeds.

The fix implements the Go-specific guidance from CWE-287, which emphasizes that password comparison must use bcrypt with constant-time semantics and that the comparison operation must run even on missing users to prevent enumeration.

## Behaviour changes

- **Authentication latency**: All login attempts now take approximately 100-300ms (depending on bcrypt cost factor) due to bcrypt computation, vs. microseconds previously. This is intentional and prevents timing attacks.
- **User enumeration**: Timing analysis can no longer distinguish valid usernames from invalid ones; both paths run bcrypt comparison.
- **Startup time**: Application startup now includes password hashing operations, negligible for test setup but would be handled via secure startup in production (e.g., loading pre-hashed credentials from a database).
- **No other functional changes**: LoginHandler's API, error messages, session cookie, and HTTP response codes remain identical. Successful login still issues a session cookie with HttpOnly and Secure flags set.
