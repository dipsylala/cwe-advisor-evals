## Verdict
Exploitable

## Source
`rand.IntN()` from `math/rand/v2` (imported at line 5)

## Sink
Line 24: `key[i] = keyAlphabet[rand.IntN(len(keyAlphabet))]` - uses weak PRNG output to select characters for an API key

## Fix

**Vulnerable code:**
```go
import (
	"fmt"
	"math/rand/v2"
	"net/http"
)

func IssueAPIKey(w http.ResponseWriter, r *http.Request) {
	account := r.FormValue("account")
	if account == "" {
		http.Error(w, "account required", http.StatusBadRequest)
		return
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = keyAlphabet[rand.IntN(len(keyAlphabet))]  // VULNERABLE: weak PRNG
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
```

**Fixed code:**
```go
import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
)

func IssueAPIKey(w http.ResponseWriter, r *http.Request) {
	account := r.FormValue("account")
	if account == "" {
		http.Error(w, "account required", http.StatusBadRequest)
		return
	}

	key := make([]byte, 32)
	for i := range key {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyAlphabet))))
		if err != nil {
			http.Error(w, "failed to generate key", http.StatusInternalServerError)
			return
		}
		key[i] = keyAlphabet[index.Int64()]
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
```

## Explanation
API keys are long-lived credentials used for authentication and must be cryptographically unpredictable. The original code uses `math/rand/v2.IntN()`, a general-purpose PRNG documented as unsuitable for security-sensitive operations; an attacker with enough observed key samples can reconstruct its internal state and predict future keys. The fix replaces the weak PRNG with `crypto/rand.Int()`, which draws from the operating system's secure random source (`getrandom` on Linux, `ProcessPrng` on Windows) and requires no seeding. The use of `big.NewInt()` with `crypto/rand.Int()` ensures uniform distribution across the alphabet without modulo bias. Error handling is added because `crypto/rand.Int()` can fail (rare but possible under OS resource exhaustion), and the HTTP 500 response signals this failure appropriately.

## Behaviour changes
- **Error handling added**: The original code did not handle randomness failures; the fixed code returns HTTP 500 if `crypto/rand.Int()` fails, which is appropriate for unrecoverable OS errors during key generation.
- **Import change**: Replaces `"math/rand/v2"` with `"crypto/rand"` and adds `"math/big"` for range-reduction without bias; no change to public API or return values.
- **Performance trade-off**: `crypto/rand.Int()` is slower than `math/rand/v2.IntN()` because it reads from the OS kernel, but this cost is negligible for a 32-character key generation at request time and is necessary for security.
- **Sink contract preserved**: The function still returns the same 32-character key and stores it in `apiKeys` identically; only the generation mechanism changed.
