## Verdict

exploitable

- cwe_id: CWE-338
- location: `RandV2ApiKey.go`, line 24 (sink); loop at lines 22-25
- confidence: high

## Source

`math/rand/v2` (`"math/rand/v2"`, imported as `rand`) via `rand.IntN(len(keyAlphabet))`, called once per byte inside the loop at line 22-25 in `IssueAPIKey`. There is no upstream attacker-controlled input feeding the generator itself - the weakness is the choice of PRNG, not tainted input reaching it. The only external input in this handler, `account := r.FormValue("account")`, is unrelated to the key material and is only used as the map key's value, not as a randomness input.

## Fix

### File: RandV2ApiKey.go

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
	alphabetSize := big.NewInt(int64(len(keyAlphabet)))
	for i := range key {
		n, err := rand.Int(rand.Reader, alphabetSize)
		if err != nil {
			http.Error(w, "failed to generate API key", http.StatusInternalServerError)
			return
		}
		key[i] = keyAlphabet[n.Int64()]
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
```

## Explanation

The sink is the byte-selection expression at line 24, `keyAlphabet[rand.IntN(len(keyAlphabet))]`, run 32 times to build a long-lived API key. `math/rand/v2`'s `IntN` is a fast, deterministic generator that the package itself documents as unsuitable for security use regardless of seeding; observing enough output lets an attacker reconstruct its internal state and predict subsequent key bytes, and the key is exactly the kind of long-lived, access-granting, externally-observable secret the knowledge base flags as a finding even though it doesn't look like a "random number" bug at first glance. The fix replaces the `math/rand/v2` import with `crypto/rand` (drawing from OS entropy, no seeding required) and swaps `rand.IntN(len(keyAlphabet))` for `rand.Int(rand.Reader, alphabetSize)`, per the Go-specific guidance's instruction to reduce `crypto/rand` output to a bounded range with `crypto/rand.Int(rand.Reader, big.NewInt(n))` rather than taking a modulus of raw bytes, which would introduce modulo bias. `alphabetSize` is computed once outside the loop from `len(keyAlphabet)` (36), matching the original bound exactly, and `n.Int64()` indexes `keyAlphabet` identically to how `IntN`'s return value did. No other logic - the account check, the map write, or the response - was touched.

## Behaviour changes

- Added error handling for `rand.Int`'s `err` return: `math/rand/v2.IntN` has no failure mode and returns a bare value, but `crypto/rand.Int` reads from the OS entropy source and can fail (e.g. exhausted/unavailable entropy source), so it returns `(*big.Int, error)`. On error the handler now responds `500 Internal Server Error` and returns before writing a partial or absent key, rather than continuing with undefined data. This is required by the new API's contract, not an unrelated addition; the practical likelihood of `crypto/rand.Int` failing on a live OS is negligible, but the code cannot silently ignore the error without risking an unchecked `n == nil` dereference at `n.Int64()`.
- All other inputs, outputs, and control flow (the `account` empty-check, the `apiKeys` map write, the response body) are unchanged.

## Verification

Copied the fixed file to a scratch module (`scratchcheck338`, `go mod init` + the single file) outside the repository and ran `go vet ./...` and `go build ./...` against Go 1.25.5 (windows/386, local toolchain) - both completed with exit code 0 and no diagnostics. Confirmed `crypto/rand.Reader`, `crypto/rand.Int`, and `math/big.NewInt` are all standard-library symbols (`crypto/rand`, `math/big` packages) newly introduced by this fix; no third-party dependency was added.
