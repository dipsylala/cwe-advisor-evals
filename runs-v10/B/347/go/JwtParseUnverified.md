## Verdict

**CWE-347 confirmed and remediable.**

The keyfunc does not validate `token.Method` before returning the RSA public key, enabling algorithm confusion. An attacker can craft a token claiming HS256 (HMAC), sign it with the public key treated as an HMAC secret, and bypass signature verification.

## Source

`JwtParseUnverified.go` lines 15–20:

```go
keyfunc := func(token *jwt.Token) (interface{}, error) {
    return rsaPublicKey, nil
}

token, err := jwt.Parse(tokenString, keyfunc)
```

The untrusted JWT comes from `r.Header.Get("Authorization")` (line 13). The keyfunc unconditionally returns `rsaPublicKey` without asserting the token's signing method, permitting the algorithm confusion attack.

## Fix

Replace the keyfunc and parser invocation with:

```go
keyfunc := func(token *jwt.Token) (interface{}, error) {
    // Restrict to RS256 only; reject algorithm confusion
    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return rsaPublicKey, nil
}

token, err := jwt.Parse(
    tokenString,
    keyfunc,
    jwt.WithValidMethods([]string{"RS256"}),
    jwt.WithExpirationRequired(),
)
if err != nil || !token.Valid {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
```

## Explanation

The fix enforces signature verification at two levels:

1. **Keyfunc method assertion** (line 2–5): The keyfunc now type-asserts `token.Method` against `*jwt.SigningMethodRSA`, ensuring only RSA-signed tokens proceed. Any token claiming HS256, HMAC, or another algorithm is rejected with an error before the public key is ever used.

2. **Parser options** (lines 9–11): `jwt.WithValidMethods([]string{"RS256"})` provides defense in depth, redundantly restricting the parser itself to RS256. This protects against future keyfunc changes. `jwt.WithExpirationRequired()` ensures tokens without an `exp` claim are rejected, closing a secondary bypass where an attacker omits expiration and the token is treated as unexpired forever.

3. **Error handling** remains intact: the code still rejects tokens with verification errors (line 13).

## Behaviour changes

- **Tokens with non-RSA algorithms** (e.g., HS256, ES256, `none`): now rejected with `"unexpected signing method"` error instead of being accepted.
- **Tokens missing the `exp` (expiration) claim**: now rejected instead of accepted as unexpired indefinitely.
- **All other valid RS256 tokens**: no change; they are accepted as before.
