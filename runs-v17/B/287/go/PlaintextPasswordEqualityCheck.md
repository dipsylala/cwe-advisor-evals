## Verdict

Exploitable. Line 47 compares passwords using direct string equality (`==`) instead of a constant-time cryptographic comparison, and the passwords are stored in plaintext. This allows both password guessing via timing analysis and straightforward plaintext password recovery.

## Source

Attacker-controlled password from the JSON request body, decoded into `req.Password` at line 35.

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
	Password string // Now holds bcrypt hash instead of plaintext
}

// userStore stands in for a database table of accounts. Passwords are now bcrypt hashes.
var userStore = map[string]*User{
	"alice": {Username: "alice", Password: "$2a$12$R9h7cIPz0gi.URNNWH3H2OPST9/PgBkqquzi.Ss7KIUgO2t0jKMm"},
}

// dummyHash is a bcrypt hash of an arbitrary string, used to mitigate timing attacks
// when the username doesn't exist in the store.
var dummyHash string

func init() {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	dummyHash = string(hashBytes)
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
	
	// Always run bcrypt.CompareHashAndPassword to prevent timing attacks that
	// reveal whether a user exists. If the user is not found, compare against
	// a dummy hash computed at startup.
	hashToCheck := dummyHash
	if ok {
		hashToCheck = user.Password
	}
	
	err := bcrypt.CompareHashAndPassword([]byte(hashToCheck), []byte(req.Password))
	if err == nil && ok {
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

The vulnerability at line 47 is a direct string comparison of plaintext passwords using `==`, which fails to use a proper password verification mechanism. This introduces two attack vectors: (1) an attacker can guess passwords by measuring response time differences between correct and incorrect submissions, since string equality is not constant-time; (2) the plaintext storage means compromise of the password database directly exposes credentials.

The fix replaces the plaintext comparison with `bcrypt.CompareHashAndPassword()`, which is a constant-time salted hash comparison function from `golang.org/x/crypto/bcrypt`. The fix also updates the password storage in `userStore` to use bcrypt hashes instead of plaintext values. To prevent user enumeration via timing attacks (where an attacker learns whether a username exists by measuring response time), the fix generates a dummy bcrypt hash at startup and always runs the bcrypt comparison even when the user is not found. This ensures that failed authentication due to a missing user takes the same time as failed authentication due to an incorrect password.

## Behaviour changes

1. **Import added**: `golang.org/x/crypto/bcrypt` is now imported.
2. **User.Password semantics changed**: The `Password` field now stores a bcrypt hash instead of plaintext password.
3. **userStore values changed**: Passwords are now bcrypt hashes instead of plaintext strings.
4. **New package variable added**: `dummyHash` stores a bcrypt hash generated at startup.
5. **New init() function added**: Generates the dummy hash for timing-attack mitigation. If hash generation fails, the process panics rather than continuing with an empty/invalid dummy.
6. **LoginHandler flow changed**: Rather than returning early when `lookupUser` fails, the handler now continues to line 53 and runs `bcrypt.CompareHashAndPassword` in all cases (either against the found user's hash or the dummy hash).
7. **Password comparison changed**: From `req.Password == user.Password` to `bcrypt.CompareHashAndPassword([]byte(hashToCheck), []byte(req.Password))`.
8. **Success condition changed**: Authentication now succeeds only if `bcrypt.CompareHashAndPassword` returns nil AND the user was found (`ok == true`). Previously it succeeded only if the string comparison was true.

The changes preserve the HTTP response contract: the handler still returns `200 OK` on successful authentication and `401 Unauthorized` on all failure cases (wrong password, missing user, malformed request).

