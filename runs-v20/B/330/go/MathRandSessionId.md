## Verdict

Confirmed. `LoginHandler` builds the `session_id` cookie value from `math/rand.Intn`, a non-cryptographic PRNG, so the session identifier is guessable by an attacker who can approximate the process's random state or brute-force the narrow output range.

## Source

`math/rand.Intn(1000000000)` at line 18 (`MathRandSessionId.go`). The value is used, unmodified, as the numeric half of the session cookie - no validation or additional entropy is mixed in between generation and the cookie sink.

## Fix

Sink contract established before changing anything:
- **Returns**: the original `rand.Intn` returns a plain `int` in `[0, 1000000000)`, immediately formatted into `sessionID` with `%d`.
- **Discards**: nothing.
- **Arguments left implicit**: none - `Intn` takes only the exclusive upper bound.
- **Failure behaviour**: `math/rand.Intn` cannot fail (panics only if `n <= 0`, not the case here). The replacement source, `crypto/rand.Int`, *can* return an error if the OS entropy source fails to read, so the fix adds an explicit error branch that the original sink never needed - this is a required, not incidental, difference.

No `go.mod` is present in the case directory, so the Go toolchain version driving `math/rand`'s auto-seeding and ChaCha8 backing (1.20/1.22/1.24 behavior) could not be confirmed. Rather than assume Go 1.24+ is available (required for `rand.Text()`), the fix uses `crypto/rand.Int`, which is available on any supported Go release and needs no version assumption. This is recorded as the operative assumption.

### File: MathRandSessionId.go
```go
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
)

// LoginHandler issues a session cookie after a successful login.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Cryptographically secure token: crypto/rand.Int draws a uniform value
	// from [0, max), sized to a 128-bit floor per OWASP ASVS.
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	token, err := rand.Int(rand.Reader, max)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
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

## Explanation

The weak generator, not just its seed, was the problem, so the fix swaps `math/rand.Intn` for `crypto/rand.Int(rand.Reader, max)`, a CSPRNG draw backed by the OS entropy source. `max` is set to `2^128` so the token alone carries at least 128 bits of entropy, meeting the OWASP ASVS floor for a non-guessable value, rather than the roughly 30 bits (`log2(1e9)`) the original range supplied. `crypto/rand.Int` masks and retries internally, so the output is uniform over `[0, max)` with no modulo bias. `*big.Int` implements `fmt.Formatter` and supports the `%d` verb directly, so the existing `fmt.Sprintf("%s-%d", username, token)` cookie-value construction, the username validation, the cookie attributes (`HttpOnly`, `Path`), and the response body are all left exactly as they were - only the token's source and type changed. Because `crypto/rand.Int` can return an error (unlike `Intn`), the fix adds a failure branch that responds with `500` rather than silently falling back to a weak generator, since a fallback to `math/rand` on error would itself reintroduce the finding. No fallback path exists, so there is nothing to rotate: this handler mints tokens on demand rather than persisting a global secret, so no previously issued value needs reissuing beyond normal cookie expiry.

## Behaviour changes

- Session ID format: the numeric suffix is still decimal digits after `username-`, but is now up to 39 digits (a value up to `2^128 - 1`) instead of at most 9 digits (`< 1e9`). Any code or test asserting a fixed-width numeric suffix on `session_id` needs updating.
- New failure mode: if the OS entropy source is unreadable, the handler now returns `500 Internal Server Error` instead of always succeeding. This is intentional - `crypto/rand.Int` is the only path that can produce this error, and no fallback to a weak generator is used to avoid it.
- No rotation was needed: the original handler generated a session ID per login rather than issuing from a persistent pool of pre-generated weak tokens, so there are no previously issued values to invalidate.

**Verification performed**: the fixed file was copied to a scratch Go module and checked with `go vet ./...` (Go 1.25.5), which type-checks the package without requiring a `main` function; it returned no diagnostics, confirming `crypto/rand.Int`'s signature, `big.NewInt`/`Lsh` usage, and `*big.Int` formatting via `%d` are all valid. The original file was not modified.
