## Verdict

Exploitable. `math/rand.Intn` is a non-cryptographic PRNG; its documentation states outputs "might be easily predictable regardless of how it's seeded." The value it produces here becomes the session identifier, so an attacker who can observe or narrow the PRNG's state (or simply brute-force the ~30-bit keyspace of `Intn(1000000000)`) can guess or forge another user's session cookie. Confidence: high.

## Source

`math/rand.Intn(1000000000)` at line 18 of `MathRandSessionId.go`, inside `LoginHandler`. The output flows unmodified into `sessionID` (line 19) and reaches the sink at `http.SetCookie` (lines 21-26), which sets it as the `session_id` cookie value with no further transformation.

## Fix

Vulnerable code:

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

	// SAST FINDING: CWE-330 (Use of Insufficiently Random Values)
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

Fixed code:

```go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
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

The fix swaps the generator, not the encoding or seed: `math/rand.Intn` is replaced with `crypto/rand.Read` filling a 16-byte buffer (128 bits of entropy, meeting the OWASP ASVS floor for a non-guessable value), then base64url-encoded with `base64.RawURLEncoding` so the result is safe to embed in a cookie value without padding characters. `crypto/rand` is backed by the OS CSPRNG and gives no seeding API, so there is no seed-related regression to introduce. The `err` check on `rand.Read` is kept for compatibility with Go toolchains older than 1.24, where a failure is a real (if practically unreachable) error rather than a fatal crash; the module's Go version could not be confirmed here since no `go.mod` was in scope, so the more defensive form was chosen. The username portion of the session ID is untouched - only the unpredictable suffix changed generator.

## Behaviour changes

- Session ID format changes from `<username>-<up to 10 decimal digits>` to `<username>-<22-character base64url string>`. Any downstream code that parses, logs, or matches on the numeric shape of the old suffix will need to accept the new format. This is required: the previous format's small, fully-numeric keyspace was the exploitable weakness.
- A new error branch (`http.StatusInternalServerError`) is introduced because `crypto/rand.Read` can fail on toolchains before Go 1.24, whereas `math/rand.Intn` never errors. On Go 1.24+ this branch is unreachable (the runtime fails fatally instead), so it adds a defensive path without materially changing normal request handling.
- No other arguments, return values, or discarded output changed; the cookie's `HttpOnly`, `Path`, and `Name` fields, and the rest of the handler's control flow, are unchanged.

**Assumptions:** No `go.mod` was present in the case directory, so the target Go version could not be confirmed. Chose `crypto/rand.Read` + `base64.RawURLEncoding` (works on all Go versions) over `rand.Text()` (Go 1.24+ only) for portability; if the module is confirmed on Go 1.24+, `rand.Text()` is the more purpose-built API per the loaded guidance. Confidence lowered from high to medium-high on the fix's API choice for this reason, though the verdict itself is unaffected.
