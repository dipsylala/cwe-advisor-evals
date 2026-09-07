## Verdict

Exploitable. The `keyFunc` callback passed to `jwt.ParseWithClaims` (line 49) returns the HMAC secret without validating that `token.Method` is the expected algorithm. An attacker can submit a token with `alg: none`, `alg: HS256` reused as the HMAC key, or other algorithm confusion attacks and bypass authentication.

## Source

Bearer token from `Authorization` header (line 34), extracted and passed to `jwt.ParseWithClaims` at line 49.

## Fix

**Vulnerable code:**
```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
	return hmacSecret, nil
}

// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
```

**Fixed code:**
```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
	// Verify the token uses HMAC signing before returning the key
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return hmacSecret, nil
}

// Token parsing with algorithm method validation and allowlist for defense-in-depth
token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, jwt.WithValidMethods([]string{"HS256"}))

// Add to imports at the top of the file:
// "fmt"
```

## Explanation

The fix adds two layers of algorithm validation. First, the `keyFunc` now asserts that `token.Method` is a `jwt.SigningMethodHMAC` before returning the secret; any other algorithm (including `SigningMethodNone`) causes `ParseWithClaims` to return an error. Second, the `jwt.WithValidMethods([]string{"HS256"})` parser option adds defense-in-depth by rejecting tokens with disallowed algorithms before the `keyFunc` is even invoked. Together, these changes prevent algorithm-confusion attacks where an attacker switches from HMAC to `alg: none` or reuses a public key as an HMAC secret. The `fmt` package import is required for the error formatting in the type assertion branch.

## Behaviour changes

1. **Added `fmt` import** - Required for `fmt.Errorf` in the algorithm validation branch.
2. **Added method type check in `keyFunc`** - Changes error handling: tokens with non-HMAC algorithms now return an explicit error instead of silently accepting the key. The error is returned to the caller and triggers the `if err != nil` branch at line 50 (unchanged in structure).
3. **Added `jwt.WithValidMethods` parser option** - Defense-in-depth validation that fails parsing for disallowed algorithms before invoking `keyFunc`. Does not alter the return type or contract of `ParseWithClaims`, only makes it stricter about which tokens proceed to parsing.

All changes preserve the sink's existing contract: `ParseWithClaims` still returns `(*jwt.Token, error)` and the caller still checks both `err` and `token.Valid` before trusting the claims.
