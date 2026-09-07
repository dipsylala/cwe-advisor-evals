## Verdict

Real vulnerability. `math/rand.Intn()` on line 18 is a non-cryptographic PRNG unsuitable for session token generation. An attacker can predict the token value given knowledge of the username and process start time, forging valid session cookies.

## Source

`math/rand.Intn()` at line 18 of MathRandSessionId.go. The package-level import (`math/rand` on line 5) brings the weak generator into scope.

## Fix

### File: MathRandSessionId.go

```go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

// LoginHandler issues a session cookie after a successful login.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Generate a cryptographically random token
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	token := base64.RawURLEncoding.EncodeToString(randomBytes)
	sessionID := fmt.Sprintf("%s-%s", username, token)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		Path:     "/",
	})

	fmt.Fprintf(w, "welcome %s", username)
}
```

## Explanation

Replaced `math/rand` import with `crypto/rand` and `encoding/base64`. The weak `rand.Intn(1000000000)` call is replaced with cryptographically secure random byte generation: `crypto/rand.Reader` fills a 32-byte buffer (256 bits of entropy, well above the 128-bit OWASP ASVS minimum for non-guessable tokens), then encoded to base64 string using `RawURLEncoding` (no padding, safe for URL contexts). The token is combined with username using the same `Sprintf` format. This eliminates the predictability: `crypto/rand` draws from the OS entropy pool and cannot be predicted by an attacker without access to that pool.

## Behaviour changes

- Session token format changes from a decimal number (e.g., "user-123456789") to a base64-encoded string (e.g., "user-AbCdEfGhIjKlMnOpQrStUvWxYz"). Cookie validation logic that inspects the token format must be updated accordingly if present elsewhere in the application.
- Token length increases from ~10 decimal characters to ~43 base64 characters (32 bytes → 43 chars with base64 encoding).
- Runtime entropy cost increases negligibly (one OS read per login instead of PRNG computation), but security guarantee improves from predictable to cryptographically random.
