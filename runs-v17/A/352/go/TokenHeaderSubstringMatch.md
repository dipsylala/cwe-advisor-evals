## Verdict
CONFIRMED

## Source
Line 11 of csrf.go uses `strings.Contains(sessionToken, headerToken)` to validate CSRF tokens. This enables substring matching, allowing an attacker to forge a valid token by supplying any substring of the legitimate session token.

## Fix

### File: csrf.go
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
The original code used substring matching instead of full token comparison. CSRF token validation requires exact equality, not substring containment. The fix replaces `strings.Contains()` with `crypto/subtle.ConstantTimeCompare()`, which:

1. Performs byte-level equality comparison of the full tokens (not substring matching)
2. Runs in constant time to prevent timing-based attacks that could reveal information about the session token
3. Returns 1 on match, 0 on mismatch, allowing the boolean logic to work correctly

This ensures only valid, unmodified tokens pass validation.
