# CWE-338 - RandV2ApiKey.go

## Verdict

Exploitable. Confidence: high.

Location: `e:/Github/cwe-advisor/evals/cases/338/go/RandV2ApiKey/RandV2ApiKey.go`, line 24.

`IssueAPIKey` builds a long-lived API key from `math/rand/v2`. That generator is a fast deterministic PRNG; it is not cryptographically secure regardless of how it is seeded. Its global source is auto-seeded from OS randomness at process start, which removes a fixed seed but does not change the algorithm - enough observed output lets an attacker reconstruct the generator's internal state and predict every subsequent draw. Each issued key is returned to its requester in the response body, so an attacker who can call the endpoint collects as much generator output as they want, in order, and can then predict the keys minted for other accounts. The predicted value is the credential itself: guessing it grants access rather than merely revealing information, and the key is long-lived, so there is no window that limits the attack.

## Source

- Source: the `math/rand/v2` global generator, drawn at line 24 via `rand.IntN(len(keyAlphabet))`.
- Flow: each draw indexes `keyAlphabet` and fills one byte of the 32-byte `key` slice.
- Sink: line 24 is the weak-randomness sink; the resulting key is then registered as a credential at `apiKeys[string(key)] = account` (line 27) and disclosed to the caller by `fmt.Fprint(w, string(key))` (line 28).

Sink contract at line 24, which the fix has to preserve:

- Returns: an `int` in `[0, 36)`, used only as an index into `keyAlphabet`. The caller stores the selected byte; the produced key is 32 characters drawn from `[a-z0-9]`.
- Discards: nothing.
- Implicit arguments: the call omits an explicit `*rand.Rand`, so it uses the package-level global source. Nothing in the surrounding code depends on that source being reproducible - there is no seeding call and no test fixture reading from it.
- Failure behaviour: `rand.IntN` cannot fail; it panics only for a non-positive bound, which cannot occur here because `keyAlphabet` is a non-empty constant. The function therefore has no failure path between the `account` check and the response.

## Fix

Vulnerable code:

```go
import (
	"fmt"
	"math/rand/v2"
	"net/http"
)

	key := make([]byte, 32)
	for i := range key {
		// math/rand/v2 is a deterministic, non-cryptographic PRNG - observed
		// keys reveal its state, so future keys are predictable.
		key[i] = keyAlphabet[rand.IntN(len(keyAlphabet))]
	}
```

Fixed code:

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

	alphabetLen := big.NewInt(int64(len(keyAlphabet)))
	key := make([]byte, 32)
	for i := range key {
		n, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			http.Error(w, "could not issue key", http.StatusInternalServerError)
			return
		}
		key[i] = keyAlphabet[n.Int64()]
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
```

No library change is required - `crypto/rand` and `math/big` are both in the Go standard library, so there is no dependency to add or version to check.

## Explanation

The key material now comes from `crypto/rand`, which reads from the operating system's CSPRNG (`getrandom(2)` on Linux, `ProcessPrng` on Windows) and needs no seeding. Unlike `math/rand/v2`, its output carries no recoverable internal state, so previously issued keys tell an attacker nothing about the next one. `crypto/rand.Int` is used rather than a modulo reduction of raw random bytes because the 36-character alphabet does not divide evenly into a byte's range; taking `%` would bias the early characters of the alphabet and shrink the effective search space. Each character is drawn uniformly from all 36 possibilities, so a 32-character key carries roughly 165 bits of entropy, well beyond guessing range. The key's length, character set, storage in `apiKeys`, and response body are all unchanged, so callers and any existing key-format validation continue to work.

## Behaviour changes

- **A failure path exists where the original had none.** `rand.Int` returns an error if the OS entropy source cannot be read, whereas `rand.IntN` could not fail. The handler now responds `500` with `could not issue key` and returns before writing to `apiKeys`, so a partially built key is never registered and never disclosed. This cannot be avoided: reading from the OS CSPRNG is inherently fallible, and ignoring the error would let a zero-valued index through. In practice this path is close to unreachable on a healthy host.
- **Imports changed.** `math/rand/v2` is replaced by `crypto/rand`, and `math/big` is added for the bounded draw. `crypto/rand`'s package name is also `rand`, so the call sites read the same way and no alias is needed.
- **`alphabetLen` hoisted out of the loop.** `big.NewInt(int64(len(keyAlphabet)))` is computed once instead of per character. This exists only because `rand.Int` takes a `*big.Int` bound where `rand.IntN` took an `int`; it does not alter the output.
- **Not changed:** key length (32), alphabet, the `account` validation and its `400` response, the `apiKeys` map write, and the response body. Randomness is no longer reproducible from a known seed, but nothing in this code depended on that.
- **Pre-existing issue, deliberately left alone:** `apiKeys` is a plain map written from an HTTP handler with no synchronisation, which is a data race under concurrent requests. It is unrelated to CWE-338 and was outside the scope of this fix.
