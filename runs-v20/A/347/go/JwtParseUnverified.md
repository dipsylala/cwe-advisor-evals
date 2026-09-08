## Verdict

Confirmed. `jwt.Parse` is handed a `keyfunc` that returns `rsaPublicKey` unconditionally, without checking `token.Method` (the algorithm named in the token's own header) against the algorithm the server actually expects. `golang-jwt/jwt` dispatches signature verification based on the `alg` header the caller supplies, so an attacker who controls the token can pick the signing method. Because the RSA public key is, by definition, public, an attacker can craft a token with `alg: HS256` and sign it using the known RSA public key bytes as the HMAC secret. If the key type happens to satisfy the HMAC verifier's `[]byte` type assertion (e.g. the key is stored/loaded as raw PEM/DER bytes rather than a parsed `*rsa.PublicKey`), the forged token verifies successfully and `token.Valid` is `true`, giving the attacker a fully forged, attacker-chosen-claims token. Even where the concrete key type would make that particular cast fail today, the code has no algorithm allowlist, so it relies entirely on an incidental type mismatch rather than an intentional check - a latent, fragile control, not a real one.

## Source

`tokenString := r.Header.Get("Authorization")` - the raw `Authorization` header is attacker-controlled input, including its algorithm header, and flows directly into `jwt.Parse` at line 20 with no algorithm restriction applied first.

## Fix

### File: JwtParseUnverified.go

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

var rsaPublicKey interface{} // loaded from server config at startup

func authMiddleware(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	}

	// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
	token, err := jwt.Parse(tokenString, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !token.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "welcome %v", claims["sub"])
}
```

## Explanation

`jwt.WithValidMethods([]string{"RS256"})` is a `golang-jwt/jwt/v5` parser option that makes the parser compare the token header's `alg` against the given allowlist *before* it ever calls `keyfunc` or attempts verification, returning `ErrTokenSigningMethodInvalid` on any mismatch. This closes the algorithm-confusion path: a token forged with `alg: HS256` (or `none`, or any RSA variant other than the one actually in use) is rejected outright, regardless of what the `keyfunc` would have returned or how the stored key happens to be typed. The fix is additive - it does not change the success path for a legitimately RS256-signed token, so no legitimate caller is affected. This is a parser-level allowlist of the cryptographic algorithm the server itself uses, not a value-format allowlist on attacker data, so it carries no risk of rejecting otherwise-valid business input. Verification: a token whose header specifies `HS256` and whose signature is anything (including one computed with the RSA public key bytes as an HMAC secret) now fails parsing with an invalid-method error before `keyfunc`/key material is even consulted, while a token correctly signed `RS256` with the real private key continues to be accepted exactly as before.
