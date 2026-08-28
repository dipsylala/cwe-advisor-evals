# CWE-338: Use of Cryptographically Weak PRNG - RandV2ApiKey.go

## Verdict

True positive. `IssueAPIKey` mints a long-lived credential, and every one of its 32 characters comes
from `math/rand/v2`. That package is a general-purpose statistical generator, not a cryptographic
one - its own documentation says it is unsuitable for security-sensitive work. The `v2` name is the
main trap here: it is a genuine improvement over `math/rand` (ChaCha8-based, automatically seeded, no
`rand.Seed` footgun), which makes it read as "the modern, safe one". It is not. `v2` fixed
predictable *seeding*; it did not make the generator's output unpredictable to an attacker who sees
some of it. The global `math/rand/v2` state is observable across the process, and its stream is not
designed to resist recovery from observed output, so an attacker holding one or two legitimately
issued keys is in a position to reason about the keys issued around them. Because the key is the
sole bearer credential for an account and never expires, guessing one is a full account takeover.

Line 24 is the reported sink; the credential is returned to the caller on line 28 and is the value
`apiKeys` is keyed by, so the weak output is the secret itself, not an incidental value.

## Source

```go
package evalcases

import (
	"fmt"
	"math/rand/v2"
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
		key[i] = keyAlphabet[rand.IntN(len(keyAlphabet))]
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
```

## Fix

```go
package evalcases

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
)

var apiKeys = map[string]string{}

// IssueAPIKey mints a long-lived API key for the named account.
func IssueAPIKey(w http.ResponseWriter, r *http.Request) {
	account := r.FormValue("account")
	if account == "" {
		http.Error(w, "account required", http.StatusBadRequest)
		return
	}

	// 24 random bytes (192 bits) encode to exactly 32 URL-safe characters.
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		log.Printf("api key generation failed: %v", err)
		http.Error(w, "could not issue key", http.StatusInternalServerError)
		return
	}
	key := base64.RawURLEncoding.EncodeToString(raw)

	apiKeys[key] = account
	fmt.Fprint(w, key)
}
```

On Go 1.24 or later the whole generation block collapses to `key := rand.Text()` (still
`crypto/rand`), which returns a 26-character base32 string carrying about 128 bits of entropy and
cannot fail. Prefer it if the module's `go` directive allows; the version above is written to build
on any Go release that supports `math/rand/v2`, so it is a safe drop-in either way.

## Explanation

**Change the generator, not the loop.** The remediation is a source swap: `math/rand/v2` out,
`crypto/rand` in. `crypto/rand.Read` draws from the operating system CSPRNG (`getrandom`,
`/dev/urandom`, `RtlGenRandom`), whose output is not reconstructible from other output. No amount of
lengthening the key, mixing in a timestamp, or re-seeding rescues a statistical PRNG, and hashing its
output only hashes a guessable input - the generator itself has to change. Note that both packages
export names like `Read` and `Int`, so the fix is only real if the `math/rand` or `math/rand/v2`
import is actually deleted; leaving it in place invites the next edit to silently reach for the weak
API again.

**Encode the bytes rather than indexing an alphabet.** The original loop maps each random value onto
a 36-character alphabet. Repeating that pattern with `crypto/rand` is possible but easy to get
subtly wrong: taking a random byte modulo 36 is biased, because 256 is not a multiple of 36 and the
first four letters therefore come up slightly more often than the rest. Doing it correctly needs
rejection sampling (draw a byte, discard anything at or above 252, then take it modulo 36) or
`rand.Int` with a big.Int bound. Encoding raw random bytes with `base64.RawURLEncoding` sidesteps the
question entirely - the encoding is a bijection, so it carries the full 192 bits through with no bias
and no rejection loop. `RawURLEncoding` (not `StdEncoding`) is deliberate: it yields `A-Za-z0-9-_`
with no `+`, `/`, or `=` padding, so the key is safe in URLs, headers, and filenames.

**Size it by entropy, not by character count.** 24 bytes gives 192 bits, comfortably past the ~128-bit
floor for a credential that never expires, and encodes to exactly 32 characters so the key's on-the-wire
length is unchanged - existing column widths and format assumptions still hold. The character set does
change, from lowercase alphanumeric to mixed-case URL-safe base64. If anything downstream validates keys
with a lowercase-only pattern or stores them case-insensitively (a `CITEXT` column, a case-insensitive
collation such as MySQL's `utf8mb4_general_ci`, or a `strings.ToLower` before lookup), it must be updated
in the same change - a case-insensitive comparison would also quietly discard about a bit of entropy per
character. If that downstream coupling cannot be touched right now, the format-preserving alternative is
the rejection-sampling loop over `keyAlphabet` described above; it keeps the exact original alphabet and
is equally sound, just more code to review.

**Fail closed.** The error branch matters. If the entropy source is unavailable, the handler returns
`500` and issues nothing. The failure mode to avoid is a fallback path that reaches for
`math/rand` when `crypto/rand` errors, which restores the vulnerability precisely when the system is
already degraded. On Go 1.24+ `crypto/rand.Read` is documented never to return an error (it panics
instead if the OS source fails), so the branch becomes dead code there - harmless, and it keeps the
function correct on older toolchains.

**Verification.** Confirm no `math/rand` import remains anywhere in the package. Generate a few
thousand keys in a test and assert they are all distinct and all 32 characters. Note that statistical
checks cannot distinguish a weak PRNG from a strong one - `math/rand/v2` output passes randomness
tests comfortably - so the assurance comes from reading the import, not from measuring the output. A
lightweight guard against regression is a lint rule: `gosec` flags this as G404, and `depguard` can
ban `math/rand` and `math/rand/v2` outright in packages that handle credentials.

**Two adjacent issues, noted rather than fixed here, since they are outside this finding.** First,
`apiKeys` is a plain map written from an HTTP handler, so two concurrent requests are a data race;
Go's map implementation detects concurrent writes and deliberately crashes the process, making this a
denial-of-service path as well as a correctness bug. It needs a mutex or `sync.Map`. Second, the map
stores the key in plaintext, so anything that can read process memory or a future persistence layer
gets every live credential. Storing a hash of the key and comparing hashes on lookup is the usual
shape - and because the key now carries 192 bits of entropy, a plain SHA-256 is sufficient there; a
slow password hash is not needed for a high-entropy random token.
