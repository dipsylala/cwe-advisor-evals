## Verdict

The finding is confirmed. Line 18 generates a session token using `math/rand.Intn()`, a non-cryptographic generator unsuitable for security-relevant values. An attacker can predict session IDs and impersonate authenticated users.

## Source

Line 18: `token := rand.Intn(1000000000)` draws from `math/rand`, which produces at most 30 bits of entropy. This value is used directly in a session cookie (lines 21–26).

The `math/rand` package is documented as suitable only for simulation and shuffling; Go's own documentation states that its outputs "might be easily predictable regardless of how it's seeded." Changing the seed or wrapping the output does not add entropy.

## Fix

Replace the `math/rand` import with `crypto/rand` and generate the session token from cryptographic randomness:

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

	// Generate a cryptographically random token (128 bits of entropy).
	tokenBytes := make([]byte, 16)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
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

**Changes:**
1. Import `crypto/rand` instead of `math/rand`
2. Add `encoding/base64` import for token encoding
3. Generate 16 random bytes (128 bits, meeting OWASP ASVS minimum) using `crypto/rand.Read()`
4. Encode as base64.RawURLEncoding (no padding, suitable for cookie values)
5. Add error handling for the read operation

## Explanation

The fix replaces the weak generator with Go's cryptographic CSPRNG (`crypto/rand`). Session IDs are security-relevant: an attacker who predicts the value gains complete user session hijacking.

`math/rand.Intn(1000000000)` produces at most 30 bits of entropy, well below the 128-bit floor for non-guessable values. The function outputs an `int` in the range [0, 10⁹), which is guessable within a small search space.

`crypto/rand.Read()` fills a buffer with bytes from the operating system's CSPRNG. The fixed code generates 16 bytes (128 bits), base64-encodes them for safe transport in cookies, and includes error handling. The cookie's `HttpOnly` flag prevents JavaScript access, and `Path="/"` ensures the cookie is browser-scope.

## Behaviour changes

**Before fix:** Session tokens were generated as integers in range [0, 10⁹) from a predictable PRNG, resulting in ~30 bits of entropy. An attacker could brute-force or predict valid session IDs.

**After fix:** Session tokens are 16 random bytes from `crypto/rand`, base64-encoded to a 24-character string (e.g., `abc1D-eFgHijKlMnOpqRsTuv`). The token carries 128 bits of cryptographic entropy, making prediction computationally infeasible. The token format changes but is opaque to the client.

**Side effects:** The session ID format changes from a numeric format (`{username}-{number}`) to alphanumeric base64 (`{username}-{base64string}`). This is a backwards-incompatible change to the session identifier format; existing session cookies will not be recognized. If session persistence is required, a migration step or session invalidation is needed.
