## Verdict

Confirmed. The keyfunc supplied to `jwt.Parse` returns `rsaPublicKey` unconditionally, without checking `token.Method`. This allows an algorithm-confusion attack: an attacker crafts a token with header `"alg": "HS256"` and signs it using the RSA public key's PEM/DER bytes as an HMAC secret. Because the public key is not secret (it can be obtained from the server's own JWKS/config), the attacker can forge a validly-"verified" token for any claims they choose. `jwt.Parse` trusts the algorithm named in the attacker-controlled token header and will invoke HMAC verification with whatever the keyfunc returns, so the forged signature checks out even though no legitimate RSA-signed token was ever produced.

## Source

`tokenString := r.Header.Get("Authorization")` (line 13) — the raw `Authorization` header is attacker-controlled and flows unmodified into `jwt.Parse` at line 20.

## Fix

```go
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var rsaPublicKey interface{} // loaded from server config at startup

func authMiddleware(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	}

	// Pin the accepted signing method(s) so the attacker-controlled "alg"
	// header can never select HMAC (or "none") verification against the
	// RSA public key.
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

`golang-jwt/v5` verifies the signature using whichever algorithm the token's own header claims, unless the caller restricts that set. Leaving it unrestricted turns the keyfunc into an oracle: an RSA public key returned for every token also gets handed to the HMAC verifier if the attacker sets `"alg": "HS256"`, and since RSA public keys are not secret, the attacker can compute a valid HMAC-SHA256 signature over a forged payload themselves. This is the classic JWT "alg confusion" variant of CWE-347 — the code checks that *a* signature validates, not that it validates under the algorithm the key material was actually meant for.

The fix pins the accepted algorithm(s) with `jwt.WithValidMethods([]string{"RS256"})` (or the appropriate RSA/ECDSA variant actually issued by the server), which makes `jwt.Parse` reject any token whose header names a different algorithm before the keyfunc's return value is ever used for verification. As defense in depth, the keyfunc itself should also assert `token.Method` matches the expected concrete type (e.g. `*jwt.SigningMethodRSA`) before returning the key, so a future refactor that drops the `WithValidMethods` option does not silently reopen the confusion. The `Bearer ` prefix strip is a minor correctness fix so the raw header value (which typically includes the scheme) is parsed as a bare token; it is not part of the CWE-347 remediation itself.
