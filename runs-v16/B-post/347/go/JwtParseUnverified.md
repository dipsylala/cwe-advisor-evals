## Verdict

CWE-347: Improper Verification of Cryptographic Signature confirmed. The keyfunc does not check `token.Method`, allowing algorithm confusion attack (RS256 → HS256 with public key as HMAC secret).

## Source

`r.Header.Get("Authorization")` at line 13 — attacker-controlled HTTP header containing a JWT.

## Fix

Replace the keyfunc (lines 15–17) and add `jwt.WithValidMethods()` option to the parser (line 20):

```go
keyfunc := func(token *jwt.Token) (interface{}, error) {
	// Restrict to RS256 only; reject algorithm confusion attacks
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return rsaPublicKey, nil
}

token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
```

Also add `jwt.WithExpirationRequired()` for defense in depth on token expiry validation (golang-jwt does not enforce `exp` by default):

```go
token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, keyfunc, 
	jwt.WithValidMethods([]string{"RS256"}),
	jwt.WithExpirationRequired())
```

## Explanation

The vulnerability stems from the keyfunc returning key material without verifying which signing algorithm the token claims. The fix adds two layers:

1. **Type assertion inside keyfunc**: Check `token.Method` against the concrete expected type `*jwt.SigningMethodRSA` and reject anything else before returning the public key. This prevents the library from treating the RSA public key as an HMAC secret.

2. **`jwt.WithValidMethods()` parser option**: Passes the allowed algorithm list to the parser as defense in depth. If the keyfunc is later refactored without the check, this option still rejects non-RS256 tokens.

3. **`jwt.WithExpirationRequired()`**: Ensures tokens without an `exp` claim are rejected; golang-jwt does not enforce this by default, leaving tokens valid indefinitely.

The fix uses `ParseWithClaims()` instead of `Parse()` to access the new options and to populate `jwt.MapClaims` for the claims type assertion at line 26 (already present, no change needed there).

## Behaviour changes

- **Stricter token validation**: Tokens with algorithms other than RS256 are now rejected with an error.
- **Expiry enforcement**: Tokens without an `exp` claim are now rejected.
- **Error path unchanged**: The existing error handling at line 21-24 still applies; invalid tokens still return 401 Unauthorized.
- **Claims parsing unchanged**: The `jwt.MapClaims` type assertion at line 26 works identically; only the parser option changes how it is populated.
- **Tokens rejected**: Any token signed with HS256, HS512, or other algorithms; any token missing `exp` claim.
- **Valid tokens unaffected**: Properly signed RS256 tokens with a future expiry continue to work.
