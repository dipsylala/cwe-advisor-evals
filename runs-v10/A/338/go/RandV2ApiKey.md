## Verdict

Real issue. The code uses `math/rand/v2.IntN()` to select random characters for an API key, but `math/rand/v2` is a weak, unseeded PRNG unsuitable for cryptographic purposes. An attacker can predict or brute-force the generated keys, compromising account security.

## Source

Line 24 uses `rand.IntN(len(keyAlphabet))` to index into the alphabet, drawing randomness from a non-cryptographic source. This is the sink for the taint (the requirement for cryptographic randomness in key generation).

## Fix

Replace `math/rand/v2` with `crypto/rand` and `math/big` to obtain cryptographically secure random integers:

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
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyAlphabet))))
		if err != nil {
			http.Error(w, "failed to generate key", http.StatusInternalServerError)
			return
		}
		key[i] = keyAlphabet[n.Int64()]
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
```

## Explanation

`math/rand/v2` is a general-purpose pseudorandom generator suitable for simulations and sampling, but not for security. It produces predictable sequences if the state can be observed or inferred. API keys require cryptographic strength — the attacker must not be able to guess or enumerate valid keys.

`crypto/rand.Int()` reads from the kernel's entropy source (via `rand.Reader`), providing unpredictable values suitable for cryptography. `math/big.Int` handles the range constraint securely without modulo bias for smaller alphabets.

Error handling ensures that if entropy generation fails, the endpoint returns a 500 error rather than silently producing a weak key.
