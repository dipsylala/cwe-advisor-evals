## Verdict

VULNERABLE. The token comparison uses substring matching instead of constant-time equality, allowing attackers to forge tokens and creating timing-based information leaks about token content.

## Source

The `ValidateToken()` function accepts two string parameters:
- `sessionToken`: server-controlled CSRF token stored in the session
- `headerToken`: attacker-controlled CSRF token from the request header

Both are provided by callers passing user-supplied request data.

## Fix

```go
package csrf

import (
	"crypto/subtle"
)

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	// Prevent timing attacks by checking length equality first and using constant-time comparison
	if len(sessionToken) != len(headerToken) {
		return false
	}

	// Use constant-time comparison to prevent timing-based attacks that could reveal token structure
	return subtle.ConstantTimeCompare([]byte(sessionToken), []byte(headerToken)) == 1
}
```

## Explanation

The original code used `strings.Contains()`, which performs substring matching and is vulnerable to two distinct attacks:

1. **Token forgery**: Substring matching accepts partial tokens. If the real token is "abc123", an attacker's token "abc" passes validation, violating the synchronizer-token pattern.
2. **Timing attack**: `strings.Contains()` exits early on first byte mismatch, allowing attackers to measure response time to infer token structure and length.

The fix replaces substring matching with `crypto/subtle.ConstantTimeCompare()`, which performs byte-for-byte equality comparison in constant time, preventing both classes of attack. The length check is added first as an early exit that does not leak timing information (equal-length tokens all take the same time to compare). The function converts strings to byte slices (required by `ConstantTimeCompare`) and checks that the return value equals 1, indicating all bytes matched.

## Behaviour changes

- The function now rejects tokens that differ in length, even if one is a substring of the other.
- Comparison now runs in constant time regardless of where tokens first differ, eliminating timing-based information leaks.
- The function still returns `false` for empty `headerToken` as a fast exit before comparison.
- Return type and signature remain unchanged; the fix is transparent to callers.
