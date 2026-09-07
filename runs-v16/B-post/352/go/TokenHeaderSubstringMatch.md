## Verdict

exploitable

## Source

`headerToken` parameter (attacker-controlled CSRF token from HTTP header)

## Fix

**Vulnerable code:**
```go
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
import "crypto/subtle"

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(sessionToken), []byte(headerToken)) == 1
}
```

## Explanation

The vulnerability is in using `strings.Contains()` to validate CSRF tokens. This performs substring matching rather than exact comparison, allowing an attacker to forge tokens by providing any string that appears as a substring within the legitimate token. For example, if the valid token is `"abc123def"`, an attacker could submit `"bc12"` and the validation would pass. The fix replaces substring matching with `crypto/subtle.ConstantTimeCompare()`, which performs an exact byte-for-byte comparison in constant time to prevent timing attacks. Constant-time comparison is essential for cryptographic tokens because it prevents attackers from inferring token values through timing side channels.

## Behaviour changes

The function now performs exact equality comparison instead of substring matching. This eliminates the substring-forgery attack vector. The comparison is performed in constant time using `crypto/subtle.ConstantTimeCompare()`, which takes two byte slices and returns 1 if they are equal, 0 otherwise—matching the original boolean-returning contract of the function. The empty-string check remains unchanged.
