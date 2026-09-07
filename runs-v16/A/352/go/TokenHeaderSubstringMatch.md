## Verdict
Vulnerable. CSRF token validation using substring matching allows an attacker to bypass token verification with a crafted token that is a substring of the legitimate session token.

## Source
```go
func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	return strings.Contains(sessionToken, headerToken)
}
```

## Fix
```go
func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	return sessionToken == headerToken
}
```

## Explanation
CSRF token validation must perform an exact, constant-time comparison. Using `strings.Contains()` permits an attacker to forge a valid CSRF token by submitting any string that appears as a substring within the user's legitimate token. This converts a cryptographic token validation into a pattern-matching operation that any prefix or suffix of the real token can satisfy.

The fix replaces substring matching with exact equality comparison using `==`. This ensures the presented token must match the session token precisely. For defence-in-depth, this should ideally be paired with a constant-time comparison function (e.g., `subtle.ConstantTimeCompare()`) to prevent timing side-channels, although the immediate vulnerability—accepting any substring—is the primary defect here.
