## Verdict

**exploitable**

## Source

`headerToken` parameter (attacker-controlled HTTP request header)

## Fix

### File: csrf.go

```go
package csrf

import (
	"crypto/subtle"
)

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(sessionToken), []byte(headerToken)) == 1
}
```

## Explanation

The original code used `strings.Contains(sessionToken, headerToken)` to validate CSRF tokens, which is fundamentally broken for two reasons. First, substring matching allows an attacker to forge a token that is a substring of a legitimate token, or vice versa, bypassing the validation entirely. Second, `strings.Contains()` is not constant-time, making it vulnerable to timing attacks where an attacker can extract information about the token by measuring response times. The fix replaces this with `crypto/subtle.ConstantTimeCompare()`, which performs full equality comparison in constant time, eliminating both the logic flaw and the timing attack vector. This is the required pattern from Go's standard library for all cryptographic token comparisons.

## Behaviour changes

**Import changes**: Added `crypto/subtle` import; removed unused `strings` import. `crypto/subtle` is part of Go's standard library (no external dependency).

**Return value**: Changed from boolean based on substring presence to boolean based on constant-time equality comparison. Functionally equivalent for identical tokens, but now correctly rejects tokens that are substrings of the session token.

**Execution characteristics**: Changed from linear-time string scan to constant-time byte comparison. The constant-time behavior prevents timing attacks that could leak information about the token.

## Verification

**Compiler check**: `go build` executed on fixed code in scratch directory completed successfully with no errors. All imports (`crypto/subtle` from standard library) verified present and correct.

**Test compilation**: The fixed function signature remains identical, preserving API compatibility with callers.

## Assumptions

None. The vulnerability is unambiguous: substring matching is insufficient for token validation, and constant-time comparison is the standard library's provided solution. `crypto/subtle` is part of Go's standard library and available in all supported Go versions.
