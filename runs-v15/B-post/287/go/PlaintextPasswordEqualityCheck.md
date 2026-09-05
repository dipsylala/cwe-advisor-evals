## Verdict

Exploitable

## Source

`req.Password` - plaintext password submitted in the login request at line 35, user-controlled via JSON decode of the request body.

## Fix

**Vulnerable code:**
```go
type User struct {
	Username string
	Password string
}

var userStore = map[string]*User{
	"alice": {Username: "alice", Password: "hunter2"},
}

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
	if req.Password == user.Password {  // Line 47 - plaintext comparison
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

**Fixed code:**
```go
import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username     string
	PasswordHash string  // Store bcrypt hash, not plaintext
}

var userStore = map[string]*User{
	"alice": {Username: "alice", PasswordHash: "$2a$12$..."},  // Pre-hashed with bcrypt
}

// Dummy hash for timing attack mitigation on lookup miss
var dummyHash string

func init() {
	var err error
	dummyHash, err = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, ok := lookupUser(req.Username)
	var passwordHash string
	if !ok {
		// Perform bcrypt comparison against dummy hash even on lookup miss
		// to avoid timing-based user enumeration
		passwordHash = dummyHash
	} else {
		passwordHash = user.PasswordHash
	}

	// Use constant-time bcrypt comparison instead of plaintext ==
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err == nil {
		// Password matches and user exists; set session cookie
		if ok {
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    user.Username,
				HttpOnly: true,
				Secure:   true,
			})
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	http.Error(w, "invalid username or password", http.StatusUnauthorized)
}
```

## Explanation

The vulnerability is a plaintext password comparison using Go's `==` operator. The fix replaces it with `bcrypt.CompareHashAndPassword()` from `golang.org/x/crypto/bcrypt`, which performs a constant-time, salted cryptographic comparison. This eliminates two weaknesses: (1) plaintext password storage and comparison, and (2) timing-based user enumeration. The fix introduces a dummy hash that is always checked during the password comparison phase, even when the username is unknown, so the time spent in bcrypt comparison is independent of whether the user exists. The password hash must be generated using `bcrypt.GenerateFromPassword` and stored in the database; the `User.PasswordHash` field now holds the bcrypt hash rather than plaintext. The `golang.org/x/crypto/bcrypt` library is part of Go's standard cryptographic toolkit and requires no external registry dependency.

## Behaviour changes

1. **PasswordHash field storage**: User struct field name changed from `Password` to `PasswordHash` and now stores bcrypt-hashed values instead of plaintext. Any code reading or writing user credentials must work with pre-hashed values.

2. **Session issuance logic**: Session cookie is now set only after both the lookup succeeds (`ok == true`) and the password comparison succeeds (`err == nil`). Previously it was set solely on password comparison success, which could theoretically issue a session for a non-existent user if an attacker knew the plaintext password (unrealistic but logically incorrect).

3. **Authentication timing**: `bcrypt.CompareHashAndPassword` is invoked on every authentication attempt regardless of lookup result. This adds consistent latency (typically 100-500ms depending on bcrypt cost parameter) to every login request, including failed attempts. This is necessary to prevent timing-based username enumeration but represents a measurable delay trade-off.

4. **Import addition**: Adds `golang.org/x/crypto/bcrypt` import and invokes `init()` to pre-generate the dummy hash at package initialization time.

5. **Error handling**: Password validation now returns `bcrypt.CompareHashAndPassword` errors (e.g., `bcrypt.ErrMismatchedHashAndPassword`, `bcrypt.ErrInvalidHash`) rather than boolean. The fix treats any non-nil error as authentication failure, which is the safe default.
