## Verdict

**Confirmed real vulnerability.** Using `math/rand.Intn()` to generate session IDs violates CWE-330. Non-cryptographic random values are predictable and unsuitable for security-relevant tokens. Session IDs must be drawn from `crypto/rand` to prevent session hijacking.

## Source

**File**: evals/cases/330/go/MathRandSessionId/MathRandSessionId.go  
**Line**: 18  
**Vulnerable code**:
```go
token := rand.Intn(1000000000)
sessionID := fmt.Sprintf("%s-%d", username, token)
```

The `math/rand` package is a non-cryptographic PRNG, documented by Go as having outputs "might be easily predictable regardless of how it's seeded." It is the taint sink for this finding.

## Fix

**Step 1: Update imports**

Replace:
```go
import (
	"fmt"
	"math/rand"
	"net/http"
)
```

With:
```go
import (
	"crypto/rand"
	"fmt"
	"net/http"
)
```

**Step 2: Replace the token generation**

Replace lines 17–19:
```go
token := rand.Intn(1000000000)
sessionID := fmt.Sprintf("%s-%d", username, token)
```

With:
```go
token, err := rand.Text()
if err != nil {
	http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
	return
}
sessionID := fmt.Sprintf("%s-%s", username, token)
```

## Explanation

The fix replaces `math/rand` with `crypto/rand` and uses `rand.Text()` (Go 1.24+), the platform's purpose-built API for generating cryptographically secure tokens. `rand.Text()` returns a 26-character string using RFC 4648 base32 alphabet with at least 128 bits of entropy—meeting OWASP ASVS requirements for non-guessable values with no additional encoding step. The format change from integer to text token is reflected in the `fmt.Sprintf` format string (from `%d` to `%s`), and error handling is added to gracefully reject the rare failure case.

## Behaviour changes

- **Session ID format**: Changes from `username-<integer>` (e.g., `alice-487521934`) to `username-<26-char-base32-string>` (e.g., `alice-ABCDEFGHIJKLMNOPQRSTUVWXYZ`)
- **Session ID length**: Increases from ~15–20 characters to ~30–35 characters
- **Performance**: Negligibly slower (one kernel call per login instead of fast PRNG operation); acceptable for login-time operations
- **Go version requirement**: Requires Go 1.24 or later for `rand.Text()`. For Go 1.23 and earlier, use `crypto/rand.Read()` with `base64.RawURLEncoding` instead:
  ```go
  b := make([]byte, 16)
  if _, err := crypto/rand.Read(b); err != nil {
      http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
      return
  }
  token := base64.RawURLEncoding.EncodeToString(b)
  ```
- **No functional regression**: Session validation, cookie lifecycle, and HttpOnly/Path attributes remain unchanged.
