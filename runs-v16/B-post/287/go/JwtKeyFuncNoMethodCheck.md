## Verdict

Exploitable

## Source

The `Authorization` header carrying a JWT token with an attacker-controlled `alg` parameter.

## Fix

**Vulnerable code** (lines 41-46):

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
	return hmacSecret, nil
}

// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
```

**Fixed code**:

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
	// Verify token.Method is HMAC before trusting the key
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return hmacSecret, nil
}

token, err := jwt.ParseWithClaims(
	tokenString,
	claims,
	keyFunc,
	jwt.WithValidMethods([]string{"HS256"}),
)
```

Also add `"fmt"` to the import block.

## Explanation

The vulnerability arises because `keyFunc` returns the HMAC secret without verifying the token's signing method, allowing an attacker to submit a token with `alg: none` or switch algorithms (e.g., from HS256 to RS256 using the public key as the HMAC secret). The fix adds two layers of defense: a type assertion inside `keyFunc` that rejects any signing method other than `SigningMethodHMAC`, and a `jwt.WithValidMethods()` parser option that further restricts acceptance to only `HS256`. This ensures the token is verified with the intended algorithm before the key is trusted, preventing algorithm-confusion attacks.

## Behaviour changes

- Added `"fmt"` import: necessary to format the error message with the attacker-supplied algorithm name from the token header.
- `keyFunc` now performs a type assertion on `token.Method` and returns an error for non-HMAC methods: changes the signature's behavior from accepting any algorithm to rejecting all but HMAC, which is the intended fix.
- `ParseWithClaims` now passes `jwt.WithValidMethods([]string{"HS256"})` as a parser option: restricts accepted methods at the parser level as a secondary defense, but does not alter the return value or error handling contract—parsing fails the same way with a validation error if an unsupported method is encountered.
- Error message now includes the algorithm from the token header for debugging: provides visibility into rejected tokens but does not change the functional contract (still returns an error, client still receives 401).
