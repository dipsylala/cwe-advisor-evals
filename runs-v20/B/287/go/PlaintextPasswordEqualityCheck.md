## Verdict

Exploitable. Confidence: high.

## Source

`req.Password`, decoded from the JSON request body in `LoginHandler` (attacker-controlled, arrives over the network with no prior validation).

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
	PasswordHash string
}

// userStore stands in for a database table of accounts. The password
// column holds a bcrypt hash of the value the user typed at signup.
var userStore = map[string]*User{
	"alice": {Username: "alice", PasswordHash: mustHash("hunter2")},
}

// dummyHash is compared against on a lookup miss so that response time
// does not reveal whether a username exists.
var dummyHash = mustHash("")

func mustHash(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hash)
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
		// Compare against a dummy hash and discard the result so an
		// unknown username takes the same time as a wrong password.
		bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(req.Password))
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err == nil {
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

The sink at line 47, `req.Password == user.Password`, compared attacker-supplied input to a plaintext-stored password with Go's `==`, which both leaks the stored credential's contents in memory/backups and does not run in constant time. The fix stores a bcrypt hash (`PasswordHash`) instead of the plaintext value and verifies with `bcrypt.CompareHashAndPassword`, which is a constant-time, salted comparison. To close the companion user-enumeration gap the same entry calls out for this pattern, the lookup-miss branch now also runs a bcrypt comparison against a precomputed `dummyHash` (discarding the result) before returning 401, so a wrong password and an unknown username take statistically indistinguishable time; without this, returning immediately on `!ok` would let an attacker time the difference between "no such user" and "wrong password" and enumerate valid usernames. `golang.org/x/crypto/bcrypt` is the library the loaded Go guidance names for this fix; the guidance gives no minimum version for bcrypt itself, so confirm the resolved version through SCA/dependency-check tooling before merging.

## Behaviour changes

- `User.Password` (plaintext) renamed/replaced with `User.PasswordHash` (bcrypt hash) - required to move off plaintext storage, which the `==` sink cannot be fixed without.
- Two new package-level items, `dummyHash` and `mustHash`, and a bcrypt comparison inserted on the lookup-miss branch - not present in the original, added to close the timing/user-enumeration gap the loaded guidance treats as part of the same fix ("time a wrong password against an unknown username; a sub-millisecond answer... is a user-enumeration oracle").
- Successful-login behaviour (issued cookie, `200 OK`) and failure behaviour (`401` with the same generic message) are unchanged from the caller's perspective - only the comparison mechanism and the unknown-user timing changed.
- New import `golang.org/x/crypto/bcrypt` - required dependency for the fix; must be present in the module's `go.mod`/`go.sum` (or vendor tree) for the build to resolve it.

## Verification

Copied the file to a scratch Go module (`go mod init`, `go get golang.org/x/crypto/bcrypt`), then ran `go vet ./...` and `go build ./...` - both clean. Added and ran a table of `net/http/httptest`-based tests covering a correct password (200), a wrong password for a known user (401), and an unknown username (401); all three passed (`go test -v ./...` - PASS).

## Assumptions

- The target module already depends on, or can add, `golang.org/x/crypto/bcrypt`; no `go.mod` was present in the case directory to update, so the dependency addition is noted here rather than in a changed manifest file.
- `PasswordHash` replacing `Password` on `User` is scoped to this file; if other files in the real application read `User.Password` outside this call chain, they would need the same rename, but no such file was in the provided call chain.
