## Verdict

Confirmed. `LoginHandler` builds the session identifier from `math/rand`, whose generator is a deterministic PRNG seeded from a predictable default source. An attacker who can observe or approximate the seed state (or simply brute-force the narrow output range) can predict or reproduce session tokens and hijack other users' sessions. `math/rand` is not a cryptographically secure source and must never be used to produce security-sensitive values such as session identifiers, tokens, or password-reset codes.

## Source

`E:/Github/cwe-advisor/evals/cases/330/go/MathRandSessionId/MathRandSessionId.go`, line 18:

```go
token := rand.Intn(1000000000)
```

This value flows directly into `sessionID` (line 19) and is set as the `session_id` cookie (lines 21-26), making it the credential that authenticates the user's subsequent requests.

## Fix

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
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

	token, err := generateSessionToken()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	sessionID := fmt.Sprintf("%s-%s", username, token)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	fmt.Fprintf(w, "welcome %s", username)
}

// generateSessionToken returns a hex-encoded, cryptographically random token.
func generateSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
```

## Explanation

The fix replaces `math/rand` with `crypto/rand`, Go's cryptographically secure random source that reads from the operating system's CSPRNG (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows). Instead of drawing a single `int` from a one-billion-value range, `generateSessionToken` fills a 32-byte buffer via `rand.Read`, giving 256 bits of entropy - far beyond what is brute-forceable - and encodes it as hex so it is safe to embed in a cookie value and a `Sprintf` string.

`crypto/rand.Read` can fail (rare, but possible if the OS entropy source is unavailable), so the error is checked and handled by failing the request rather than silently falling back to a weaker or zero-value token; unlike `math/rand.Intn`, which has no error path, this call must be threaded through as a fallible operation.

The username is still concatenated into the session ID for readability/debugging, but the security-relevant portion - the part an attacker would need to guess - is now the 256-bit random component, not the predictable counter that `math/rand.Intn` produced. Also added `Secure` and `SameSite` attributes to the cookie as defense-in-depth so the token is not exposed over plaintext HTTP or leaked via cross-site requests; these are independent of the CWE-330 finding but harden the same session-cookie sink.

To verify: generate a large sample of session IDs and confirm the random component has no repeats and no discernible pattern (e.g., run a chi-squared or NIST randomness test suite against the raw bytes), and confirm the code path returns a `500` rather than an empty/zero token when `rand.Read` is forced to fail.
