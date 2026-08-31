## Verdict

exploitable (confidence: high)

## Source

`r.Header.Get("Authorization")` (`JwtParseUnverified.go`, line 13) - the raw `Authorization` header, fully attacker-controlled, flows unmodified into `jwt.Parse(tokenString, keyfunc)` at line 20.

## Fix

Vulnerable code:

```go
keyfunc := func(token *jwt.Token) (interface{}, error) {
    return rsaPublicKey, nil
}

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
token, err := jwt.Parse(tokenString, keyfunc)
if err != nil || !token.Valid {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
```

Fixed code:

```go
keyfunc := func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return rsaPublicKey, nil
}

token, err := jwt.Parse(tokenString, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
if err != nil || !token.Valid {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
```

## Explanation

The `keyfunc` returned `rsaPublicKey` unconditionally, without checking `token.Method` or `token.Header["alg"]`. `golang-jwt` (whose own README carries a security notice on exactly this point) picks the verification algorithm from the token's own header, so an attacker who knows the server's RSA public key (routinely exposed via a JWKS endpoint or bundled client code, since it is a *public* key) can craft a token with `"alg":"HS256"` and sign it by computing an HMAC using the PEM-encoded public key as the shared secret. The keyfunc hands that same public key back regardless of the declared algorithm, `jwt.Parse` then verifies the token as HS256 using it, the attacker-computed HMAC matches, and `token.Valid` comes back `true` for a token the attacker forged entirely - a classic RS256-to-HS256 key-confusion bypass, not a case of missing verification but of verification with the wrong, attacker-selected key type. The fix closes this at both points the guidance calls for: the keyfunc now type-asserts `token.Method` against `*jwt.SigningMethodRSA` and returns an error for anything else before releasing key material, and `jwt.WithValidMethods([]string{"RS256"})` is added as a parser-level allowlist so the accepted algorithm is fixed independently of the keyfunc, per the library's own recommended defense-in-depth pattern.

## Behaviour changes

- Tokens signed with any algorithm other than RS256 - including a legitimately-issued HS256 or ES256 token, if the issuer ever emits one - are now rejected with the generic "unauthorized" response instead of being accepted or rejected inconsistently. This is the intended effect of the fix: the server should only ever accept the one signing method its issuer actually uses, per the loaded guidance, and nothing in the surrounding code (a single `rsaPublicKey` variable, described as the RSA key loaded at startup) indicates any other algorithm is legitimate here.
- No change to the success path: a genuine RS256 token signed with the corresponding private key still parses, `claims["sub"]` is still read from `token.Claims.(jwt.MapClaims)`, and the response body is unchanged. The keyfunc's return value and the sink's return/error contract are otherwise preserved.
