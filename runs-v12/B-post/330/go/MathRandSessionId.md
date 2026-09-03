## Verdict

Exploitable. The session ID is generated using `math/rand.Intn()`, which is non-cryptographic and produces predictable values, allowing an attacker to forge valid session cookies.

## Source

Line 18: `token := rand.Intn(1000000000)` draws from the non-cryptographic generator `math/rand`.

The token is used directly on line 19 to construct the session ID: `sessionID := fmt.Sprintf("%s-%d", username, token)`, which is then set as a cookie value on lines 21–26.

## Fix

**Vulnerable code:**
```go
package main

import (
	"fmt"
	"math/rand"
	"net/http"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	token := rand.Intn(1000000000)
	sessionID := fmt.Sprintf("%s-%d", username, token)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		Path:     "/",
	})

	fmt.Fprintf(w, "welcome %s", username)
}
```

**Fixed code (Go 1.24+):**
```go
package main

import (
	"crypto/rand"
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

	token := rand.Text()
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

**Fixed code (Go < 1.24, using `crypto/rand.Read`):**
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

	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
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

The original code uses `math/rand.Intn()`, which Go explicitly documents as unsuitable for security-relevant values because its outputs "might be easily predictable regardless of how it's seeded." Session IDs must be unpredictable to prevent forging valid cookies. The fix replaces the non-cryptographic generator with Go's `crypto/rand` package, which provides cryptographically secure randomness backed by the operating system.

For Go 1.24+, `rand.Text()` is the purpose-built API for this exact use case, returning a 26-character string with at least 128 bits of entropy, eliminating the need for manual encoding. For older Go versions, `crypto/rand.Read()` fills a byte slice with cryptographic random data, which is then base64-encoded for safe use in HTTP cookies. The fix also updates the format string from `"%s-%d"` to `"%s-%s"` to accommodate the string token instead of an integer.

## Behaviour changes

- **Import change**: `"math/rand"` is removed and `"crypto/rand"` is added. For older Go versions, `"encoding/base64"` is also added. This is necessary to access the cryptographic random source.
- **Token type change**: The token changes from an integer (produced by `Intn()`) to a string (produced by `rand.Text()` or base64 encoding). This is essential because `crypto/rand.Text()` returns a string and base64 encoding produces a string. The session ID format string is updated accordingly.
- **Error handling (Go < 1.24 only)**: The `rand.Read()` call introduces an error check with an `http.Error()` response. This is necessary because even though `crypto/rand.Read()` is documented to never return an error on Go 1.24+, earlier versions return real errors. The fallback to `math/rand` is not viable (it is itself the finding), so the handler must reject the request if random data cannot be obtained—a rare occurrence in practice.
- **Session ID entropy**: The entropy of the session ID increases from ~30 bits (log₂(1,000,000,000) ≈ 30) to 128 bits for `rand.Text()` or 16 bytes of `crypto/rand` (128 bits), meeting OWASP ASVS requirements for non-guessable values and eliminating the predictability weakness.
