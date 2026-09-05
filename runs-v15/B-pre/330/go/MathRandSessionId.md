## Verdict

CONFIRMED. Line 18 uses `math/rand.Intn()` to generate a session token, which produces predictable pseudo-random values unsuitable for security-relevant use. Session tokens must be unpredictable to prevent session hijacking and fixation attacks.

## Source

**File**: MathRandSessionId.go  
**Line**: 18  
**Code**: `token := rand.Intn(1000000000)`

The `math/rand` package is imported on line 5. Its `Intn()` method is documented as unsuitable for security-relevant values. The resulting token is used immediately to construct a session cookie value on line 19, making this a direct security path.

## Fix

**Vulnerable Code**:
```go
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

	token := rand.Intn(1000000000)  // WEAK: predictable random source
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

**Fixed Code**:
```go
import (
	"crypto/rand"
	"fmt"
	"net/http"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	token := rand.Text()  // STRONG: cryptographically secure token
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

The fix replaces the weak `math/rand.Intn()` call with `crypto/rand.Text()`, which is the purpose-built API in Go 1.24+ for generating security-relevant tokens. `rand.Text()` returns a cryptographically random string using the RFC 4648 base32 alphabet with at least 128 bits of entropy—no separate encoding step needed. The import is changed from `"math/rand"` to `"crypto/rand"`, and the token is now incorporated directly into the session ID string as-is, preserving the existing session ID format. This eliminates predictability while maintaining backward compatibility with the session ID structure.

## Behaviour changes

- **Token format**: The session token is now a 26-character RFC 4648 base32 string instead of a 10-digit decimal number. Session IDs will appear as `username-<26-char-random-string>` instead of `username-<10-digit-number>`.
- **Entropy**: The token now carries at least 128 bits of cryptographic entropy instead of approximately 30 bits from a 10-digit number, making session hijacking computationally infeasible.
- **API contract**: `crypto/rand.Text()` returns a single `string` value with no error return. Error handling is not needed; the function crashes the program irrecoverably on kernel failures (Go 1.24+ behaviour), which is appropriate for generating session tokens.
