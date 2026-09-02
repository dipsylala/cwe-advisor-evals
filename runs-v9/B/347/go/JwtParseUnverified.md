## Verdict

Exploitable. High confidence.

## Source

`r.Header.Get("Authorization")` at line 13 - the raw bearer token string is attacker-controlled and flows unmodified into `jwt.Parse` at line 20.

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

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
token, err := jwt.Parse(tokenString, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
if err != nil || !token.Valid {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
```

## Explanation

The keyfunc at line 15-17 returns `rsaPublicKey` for any token regardless of its `alg` header, so a token whose header claims `HS256` is handed the RSA public key back as the HMAC secret. Because an RSA public key is not secret, an attacker who obtains it (it is routinely exposed via JWKS or embedded in client code) can forge a valid HS256 signature over arbitrary claims, and `jwt.Parse` at line 20 will accept it - a classic algorithm-confusion bypass of signature verification (`golang-jwt/jwt` documents this exact risk). The fix type-asserts `token.Method` against `*jwt.SigningMethodRSA` inside the keyfunc and rejects any other algorithm before key material is returned, and adds `jwt.WithValidMethods([]string{"RS256"})` as a parser-level allowlist so the accepted algorithm is enforced independently of the keyfunc logic. Together these ensure the RSA public key can only ever be used to verify an RS256 signature, closing the confusion path while leaving legitimate RS256 tokens unaffected.

## Behaviour changes

A token signed with any algorithm other than `RS256` (including a forged `HS256`/`none` token, or a legitimately RS256-signed token whose header was altered to another family) now fails with `token.Valid == false` / a non-nil `err` and is rejected with 401, where previously an HS256-forged token using the RSA public key as the HMAC secret would have been accepted. No other differences: the success path for a genuine RS256 token, the returned key material for that path, the error/401 handling, and the claims extraction and response at lines 26-27 are all unchanged.
