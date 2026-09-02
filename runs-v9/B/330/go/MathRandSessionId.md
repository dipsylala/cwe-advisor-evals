## Verdict

- **CWE ID:** CWE-330 (Use of Insufficiently Random Values)
- **Location:** `MathRandSessionId.go`, line 18
- **Verdict:** exploitable
- **Confidence:** high

## Source

- **Source:** `rand.Intn(1000000000)` at line 18 (`math/rand`, a non-cryptographic PRNG)
- **Sink:** the value flows unmodified into `sessionID := fmt.Sprintf("%s-%d", username, token)` (line 19) and is then set as the `session_id` cookie via `http.SetCookie` (lines 21-26). The cookie is the session identifier issued to an authenticated user, so its unpredictability is the property that keeps a session from being guessed or brute-forced.
- Formatting the integer into a string does not add entropy - the session ID remains fully determined by the ~30 bits `Intn(1000000000)` can produce (`log2(1e9) ≈ 29.9`), far below the 128-bit floor for a non-guessable value.

## Fix

No third-party library is needed - the replacement is Go's standard `crypto/rand` package.

Vulnerable code:

```go
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
token := rand.Intn(1000000000)
sessionID := fmt.Sprintf("%s-%d", username, token)
```

Fixed code:

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

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
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

## Explanation

The `math/rand` import is replaced with `crypto/rand`, the OS-backed CSPRNG. The fix draws 16 raw bytes (128 bits, meeting the OWASP ASVS floor for a non-guessable value) with `rand.Read` and encodes them with `base64.RawURLEncoding` - the padding-free, URL-safe encoding appropriate for a value carried in a cookie. `rand.Read` is kept behind an error check because, on Go toolchains before 1.24, it can return a real error; on 1.24+ it never fails and instead panics fatally, so the branch is inert but harmless there and load-bearing on older toolchains. No `go.mod` is present in the case directory to pin the exact Go version, so the fix uses the version-portable `rand.Read` + `base64` pattern rather than the newer `rand.Text()` helper (Go 1.24+), which needs no separate encoding step but would assume a toolchain floor this trace could not confirm. Only the token's generation and encoding changed; the cookie's other attributes (`HttpOnly`, `Path`) and the surrounding handler logic are untouched.

## Behaviour changes

- **Token type and cookie format**: the token changes from an integer (up to 10 digits) to a 22-character base64url string, and the `Sprintf` verb changes from `%d` to `%s` to match. This lengthens the `session_id` cookie value; required because a 128-bit CSPRNG output cannot be represented as a `%d`-formatted small integer without discarding entropy.
- **New error path**: `rand.Read` can return an error (guaranteed only on pre-1.24 toolchains), which the original `rand.Intn` call could never do. Added a `500 Internal Server Error` response on that failure rather than proceeding with an unset or partial token. This is new failure-handling required by the safer API's contract, not a change to the success path's behaviour.
- **Previously issued session IDs**: this fix only changes generation going forward. Any `session_id` cookies already issued by the vulnerable code remain guessable until they expire or are explicitly revoked; rotating or invalidating those is an operational follow-up outside this code change.
- No other differences: cookie attributes (`HttpOnly`, `Path`), the username validation branch, and the response body are unchanged.
