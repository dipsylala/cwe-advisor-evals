## Verdict

**Confirmed:** CWE-330 - The session ID generation relies on `math/rand.Intn()`, a non-cryptographic generator whose output is "easily predictable" per Go's documentation. An attacker can enumerate plausible session IDs, forging authentication without the victim's password.

## Source

**Data flow:**
1. Line 18: `token := rand.Intn(1000000000)` — draws from non-cryptographic generator
2. Line 19: `sessionID := fmt.Sprintf("%s-%d", username, token)` — combines username with weak random value
3. Lines 21-26: `http.SetCookie()` — stores predictable sessionID as authentication credential

The sink is `math/rand.Intn()` at line 18. The value is security-relevant: it is the sole non-username component of a session token used to authenticate HTTP requests.

## Fix

### File: MathRandSessionId.go

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

// LoginHandler issues a session cookie after a successful login.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Generate a cryptographically random token for the session ID.
	randomBytes := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, randomBytes)
	if err != nil {
		http.Error(w, "failed to generate session token", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(randomBytes)
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

The fix replaces `math/rand.Intn()` with `crypto/rand.Reader`, Go's cryptographic PRNG backed by the operating system. The replaced code:

1. Allocates 16 bytes of buffer (128 bits of entropy, meeting OWASP ASVS minimums for non-guessable values)
2. Calls `io.ReadFull(rand.Reader, randomBytes)` to fill it with cryptographically random bytes
3. Encodes the bytes as hex (32 characters, no padding) so the token is printable and URL-safe
4. Combines the hex token with the username for the session ID

The Go standard library guarantees `crypto/rand.Reader` is non-predictable across process instances. The error check is retained for compatibility with Go releases before 1.24, where `io.ReadFull` can return an error; on 1.24+ it fails fatally rather than returning an error, but the check remains harmless.

## Behaviour changes

- **Token size:** The new token is 32 hex characters (128 bits of entropy) instead of up to 10 decimal digits (at most ~30 bits of entropy). Session IDs are now longer in the cookie and URL parameter if any.
- **Token entropy:** The token is now drawn from the cryptographic PRNG instead of the non-cryptographic general-purpose generator, eliminating predictability.
- **Error handling:** A failure to generate random bytes now returns HTTP 500 to the client instead of allowing login to proceed with a weak token. This is the correct security posture: session generation must not degrade to predictable values.
- **Runtime import changes:** Removed `math/rand`, added `crypto/rand`, `encoding/hex`, and `io`.
