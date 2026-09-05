## Verdict

Exploitable. The token validation uses substring matching instead of exact equality, allowing an attacker to forge a CSRF token by providing any string that is a substring of the victim's valid session token.

## Source

**Location**: `evals/cases/352/go/TokenHeaderSubstringMatch/csrf.go`, line 11

**Source**: `headerToken` parameter (attacker-controlled, supplied via HTTP header)

**Sink**: `strings.Contains(sessionToken, headerToken)` 

The `ValidateToken` function compares a session token against a header-supplied token using `strings.Contains()`, which checks if `headerToken` appears anywhere as a substring within `sessionToken`. This is a substring match, not an exact equality check.

## Fix

**Vulnerable code**:
```go
package csrf

import "strings"

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
	return strings.Contains(sessionToken, headerToken)  // VULNERABLE: substring match
}
```

**Fixed code**:
```go
package csrf

import "crypto/subtle"

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	// Use constant-time comparison for exact token match to prevent timing attacks and substring bypasses
	return subtle.ConstantTimeCompare([]byte(sessionToken), []byte(headerToken)) == 1
}
```

## Explanation

The fix replaces substring matching with exact-equality comparison using `crypto/subtle.ConstantTimeCompare()`, which returns 1 if the tokens match exactly and 0 otherwise. This eliminates the substring-match bypass: an attacker can no longer pass a forged token that is merely a substring of the valid token. The use of constant-time comparison prevents timing-based attacks where an attacker measures validation response time to infer whether token prefixes are valid, a secondary vulnerability in token validation functions. The `strings` import is removed since `strings.Contains()` is no longer used, and `crypto/subtle` is imported to provide the constant-time comparison function.

## Behaviour changes

- **Changed from substring matching to exact equality**: The original code accepted any `headerToken` that appeared anywhere within `sessionToken` as a valid match. The fixed code requires the tokens to be exactly equal (byte-for-byte).
- **Added constant-time comparison**: The fixed code uses `subtle.ConstantTimeCompare()` instead of a direct equality operator, which executes in time independent of where (or whether) the strings differ. This prevents timing-based attacks that could otherwise leak information about valid token prefixes.
- **Import change**: Removed `"strings"` (no longer needed), added `"crypto/subtle"` (required for constant-time comparison).

All other behavior is preserved: the function still returns `false` for empty `headerToken`, and returns a boolean result as before.
