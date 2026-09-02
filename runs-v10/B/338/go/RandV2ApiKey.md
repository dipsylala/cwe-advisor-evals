## Verdict

**CWE-338: Use of Cryptographically Weak PRNG**

The code uses `math/rand/v2.IntN()` to generate API key bytes, which is not cryptographically secure. Attackers with knowledge of the Go version, process start time, or observed outputs can predict future API keys, compromising authentication.

## Source

**File**: RandV2ApiKey.go, line 24

**Vulnerable code**:
```go
key[i] = keyAlphabet[rand.IntN(len(keyAlphabet))]
```

The vulnerability is in the use of `rand.IntN()` from `math/rand/v2` for security-sensitive key generation, even though the global source auto-seeds from OS randomness since Go 1.22. The package documentation explicitly warns that `math/rand` output "might be easily predictable regardless of how it's seeded"; sufficient observed output allows an attacker to reconstruct the generator's internal state.

## Fix

Replace `math/rand/v2` with `crypto/rand.Int()` for cryptographically secure index selection:

```go
package evalcases

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
)

const keyAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

var apiKeys = map[string]string{}

// IssueAPIKey mints a long-lived API key for the named account.
func IssueAPIKey(w http.ResponseWriter, r *http.Request) {
	account := r.FormValue("account")
	if account == "" {
		http.Error(w, "account required", http.StatusBadRequest)
		return
	}

	key := make([]byte, 32)
	for i := range key {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyAlphabet))))
		if err != nil {
			http.Error(w, "key generation failed", http.StatusInternalServerError)
			return
		}
		key[i] = keyAlphabet[idx.Int64()]
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
```

**Changes**:
1. Remove import of `math/rand/v2`
2. Add imports: `crypto/rand`, `math/big`
3. Replace `rand.IntN(len(keyAlphabet))` with `crypto/rand.Int(rand.Reader, big.NewInt(int64(len(keyAlphabet))))` to avoid modulo bias
4. Add error handling for the `crypto/rand.Int()` call

## Explanation

`crypto/rand.Int()` draws random bits from the cryptographically secure OS random source (`/dev/urandom` on Unix, `ProcessPrng` on Windows) and reduces the result to the requested range using rejection sampling. This eliminates modulo bias and ensures unpredictability. The 32-byte key length is preserved. Error handling is necessary because `crypto/rand.Int()` can fail if the OS random source is unavailable, which is the appropriate failure mode for key generation.

## Behaviour changes

**Runtime effect**: Each call to `IssueAPIKey` now generates cryptographically unpredictable keys instead of pseudorandom ones. The API key format (32 characters from the alphabet) remains unchanged. On platforms where the OS random source is unavailable or slow, key generation may be marginally slower, but this is the necessary tradeoff for cryptographic security.

**Error handling**: Key generation now returns HTTP 500 if `crypto/rand` fails; previously, weak key generation would silently succeed. This is appropriate for a security-critical operation.

**Observability**: There is no change to the API or logging; consumers see only that keys are now genuinely unpredictable.
