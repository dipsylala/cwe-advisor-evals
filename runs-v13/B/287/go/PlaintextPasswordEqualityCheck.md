## Verdict

Exploitable. Line 47 compares passwords using the Go equality operator (`==`) on plaintext values without a constant-time comparison function or hashing. An attacker can:
1. Perform timing-based attacks to distinguish valid usernames from invalid ones, and extract valid passwords through character-by-character timing measurements.
2. Forge successful authentication if password storage or transmission is compromised without hashing to slow extraction.

## Source

User-supplied password from the JSON request body in the `LoginHandler` at line 34–38, decoded into `req.Password`.

## Fix

**Vulnerable code (line 40–56):**

```go
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
```

**Fixed code:**

```go
import (
	"golang.org/x/crypto/bcrypt"
)

// Dummy hash generated at package init to mitigate user enumeration.
// Must be generated with bcrypt.GenerateFromPassword at the same cost as production hashes.
var dummyHash string

func init() {
	var err error
	dummyHash, err = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
}

// User represents an account record loaded from the user store.
type User struct {
	Username     string
	PasswordHash string // Changed: now stores bcrypt hash, not plaintext
}

// userStore stands in for a database table of accounts. Passwords must be pre-hashed
// before storing; do not hash on every login.
var userStore = map[string]*User{
	"alice": {Username: "alice", PasswordHash: "$2a$10$...(bcrypt hash of 'hunter2')..."},
}

// LoginHandler authenticates a user against the stored credentials and
// issues a session cookie on success.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid username or password", http.StatusBadRequest)
		return
	}

	// Lookup the user but always perform constant-time verification
	user, ok := lookupUser(req.Username)
	
	// Use a real hash on success, dummy hash on miss to prevent user enumeration
	hashToCheck := dummyHash
	if ok {
		hashToCheck = user.PasswordHash
	}
	
	// Constant-time comparison using bcrypt
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

	// Failure message is identical whether user exists or password is wrong
	http.Error(w, "invalid username or password", http.StatusUnauthorized)
}
```

## Explanation

The original code uses the `==` operator to compare plaintext passwords, which is vulnerable in two ways: (1) it performs a non-constant-time comparison that leaks password length and character-by-character timing information to an attacker monitoring response latency, and (2) it stores passwords unhashed, so any compromise of the storage layer exposes all credentials in plaintext.

The fix introduces three changes:

1. **Bcrypt hashing**: Passwords are now hashed using `golang.org/x/crypto/bcrypt` at a configurable work factor (`bcrypt.DefaultCost`). The `User.PasswordHash` field stores the hash, not the plaintext password. During login, the submitted password is checked against the stored hash using `bcrypt.CompareHashAndPassword()`, which performs a constant-time comparison that mitigates timing-based attacks.

2. **User enumeration defense**: A dummy hash is generated at package initialization using the same bcrypt parameters as production hashes. When `lookupUser()` fails (unknown username), the handler uses the dummy hash instead of returning early. Both branches—known user with wrong password and unknown user—call `bcrypt.CompareHashAndPassword()`, which always performs the same work, preventing attackers from timing the response to determine which usernames exist.

3. **Authentication check clarity**: The fixed code performs the verification in one place with a single condition (`err == nil && ok`), making it unambiguous that both the hash comparison and the user lookup must succeed for authentication to proceed.

The fix requires that passwords in the `userStore` be pre-hashed before storage (in a real application, hashing occurs at signup time, not on every login). The `bcrypt` library is part of the Go extended crypto libraries and imposes negligible overhead on login performance while closing both the timing oracle and credential-extraction attack surfaces.

## Behaviour changes

1. **Data model change**: The `User.Password` field is renamed to `PasswordHash` and now contains a bcrypt hash string instead of plaintext. Any code that relies on plaintext passwords—such as password reset emails or debug logs—must be updated or removed.

2. **Init function added**: A package-level `init()` function generates the dummy hash at startup. This is a one-time operation that succeeds or panics; if `bcrypt.GenerateFromPassword` fails, the program exits rather than silently skipping the enumeration defense.

3. **Always-execute comparison**: The comparison with `bcrypt.CompareHashAndPassword()` now runs on every login attempt, including unknown usernames. The original code returned early on lookup failure; the fixed code always performs the bcrypt work to hide the user-enumeration timing channel. This adds ~100–300 ms per failed attempt (proportional to `bcrypt.DefaultCost`), which is the intended security trade-off.

4. **Error handling**: The original code checked a boolean condition (`if req.Password == user.Password`); the fixed code checks the error return from `bcrypt.CompareHashAndPassword()` and separately verifies the user exists. Both branches (user not found and password wrong) produce the same HTTP 401 response and message, which is the intended behaviour; no new failure modes are introduced.
