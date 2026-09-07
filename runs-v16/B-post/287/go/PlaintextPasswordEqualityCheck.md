## Verdict

Exploitable. The application performs plaintext string comparison (`req.Password == user.Password`) against stored user passwords without hashing, bypassing fundamental password authentication security.

## Source

User-supplied password from the HTTP request body (`loginRequest.Password` at line 28), decoded from JSON and used in authentication logic without cryptographic validation.

## Fix

**Vulnerable code (line 47):**
```go
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
```

**Fixed code:**
```go
package auth

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string
	Password string // Now stores bcrypt hash, not plaintext
}

// dummyHash is generated at startup for timing-attack mitigation on user-not-found and SSO-only accounts
var dummyHash string

func init() {
	hash, err := bcrypt.GenerateFromPassword([]byte(""), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	dummyHash = string(hash)
}

var userStore = map[string]*User{
	// Password is bcrypt hash of "hunter2" at DefaultCost
	"alice": {Username: "alice", Password: "$2a$10$r9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"},
}

func lookupUser(username string) (*User, bool) {
	user, ok := userStore[username]
	return user, ok
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, ok := lookupUser(req.Username)
	
	// Select hash to compare: dummy if user not found or password empty, otherwise stored hash
	hashToCompare := dummyHash
	if ok && user.Password != "" {
		hashToCompare = user.Password
	}
	
	// Use constant-time bcrypt comparison instead of plaintext ==
	err := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(req.Password))
	
	// Only set cookie if user exists, password is stored, and comparison succeeded
	if ok && user.Password != "" && err == nil {
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

The vulnerability is a plaintext password comparison using Go's `==` operator. The fix replaces this with `bcrypt.CompareHashAndPassword()`, which provides:

1. **Cryptographic hashing**: Passwords are stored as bcrypt hashes, not plaintext. Bcrypt with DefaultCost (10) is a slow, salted, iterative hash resistant to brute-force and precomputation attacks.

2. **Constant-time comparison**: `bcrypt.CompareHashAndPassword()` compares hashes in constant time, preventing timing-based password enumeration where an attacker measures response time to learn whether a submitted password is correct.

3. **Timing-attack mitigation**: On user-not-found or empty-password cases (e.g., SSO-only accounts), the code still calls `bcrypt.CompareHashAndPassword()` against a dummy hash, so the response time is indistinguishable from a successful lookup, preventing username enumeration. Without this, a correct username and wrong password takes the full bcrypt time; a wrong username returns instantly, revealing which accounts exist.

4. **User validation before authentication success**: The cookie is only set when three conditions hold: user found, stored password is not empty, and bcrypt comparison succeeds. This prevents accidentally accepting users with null or missing passwords.

## Behaviour changes

1. **Password storage format**: Stored passwords change from plaintext strings to bcrypt hashes. Any password initialization or migration must rehash credentials with `bcrypt.GenerateFromPassword()`.

2. **Authentication timing**: Both successful and failed authentications now spend `O(bcrypt.DefaultCost)` time in password comparison (approximately 100ms per login attempt at cost 10), preventing timing-based attacks. This is intentional and necessary for security.

3. **Failed username handling**: User-not-found cases now incur the same bcrypt comparison time as failed-password cases, preventing timing-based username enumeration. This is a security hardening with no functional impact on legitimate users.

4. **Empty password handling**: Accounts with empty stored passwords (SSO-only users) now return `Unauthorized` with timing equivalent to a wrong password, instead of potentially failing differently.

5. **Import addition**: New dependency on `golang.org/x/crypto/bcrypt` for the `CompareHashAndPassword()` and `GenerateFromPassword()` functions.

## Verification

Compiled with `go build` against Go 1.22+ to verify the fixed code:
- All imports resolve correctly; `golang.org/x/crypto/bcrypt` is in the Go standard ecosystem.
- Function signatures match: `bcrypt.CompareHashAndPassword([]byte, []byte) error` matches the usage pattern.
- Conditional logic verified: only sets the session cookie when user found AND password stored AND bcrypt comparison succeeds.

No existing test suite provided to verify functional behaviour, but the fix preserves the login flow's interface: accepts the same request format, returns the same HTTP response codes and cookie, and maintains the same error message.
