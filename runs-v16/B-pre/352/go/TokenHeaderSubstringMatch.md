## Verdict

Exploitable. The vulnerable code uses `strings.Contains()` to validate CSRF tokens, allowing two distinct attacks: substring matching allows an attacker to craft a token that is a substring of the real token, and the timing-variant comparison leaks token length via timing side-channels.

## Source

The two parameters `sessionToken` and `headerToken` are external inputs: `headerToken` from an HTTP request header and `sessionToken` from the server session store. Both are attacker-influenced in a CSRF scenario.

## Fix

**Vulnerable code:**
```go
package csrf

import "strings"

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
	return strings.Contains(sessionToken, headerToken)
}
```

**Fixed code:**
```go
package csrf

import "crypto/subtle"

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(sessionToken), []byte(headerToken)) == 1
}
```

## Explanation

The fix replaces substring matching with exact equality comparison using Go's standard library `crypto/subtle.ConstantTimeCompare()`. This function performs a constant-time byte-slice comparison, preventing both semantic bypass (substring injection) and timing side-channel attacks. The function returns 1 when the byte slices are equal and 0 otherwise, so the return value is compared against 1 and converted back to boolean. The empty-check for `headerToken` is preserved to maintain the original guard clause.

## Behaviour changes

- Changed from `strings.Contains()` substring matching to exact equality via `subtle.ConstantTimeCompare()`. This is semantic—the original accepted any superset of the header token as valid, which is incorrect for CSRF token validation and violates the expected contract that tokens match exactly.
- Changed from timing-variant to constant-time comparison, eliminating a timing side-channel that could leak token length.
- Changed import from `strings` to `crypto/subtle` (from Go standard library).
- Return value computed from `subtle.ConstantTimeCompare()`'s int result (1 or 0) converted to boolean via comparison operator, rather than direct boolean from `Contains()`.
