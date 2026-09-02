## Verdict

Confirmed. The token's signature is accepted without the algorithm being pinned to the one the server actually intends, which allows an algorithm-confusion attack to forge a valid token.

## Source

`tokenString := r.Header.Get("Authorization")` (line 13) — the raw `Authorization` header is attacker-controlled input passed directly into signature verification.

## Fix

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

	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "welcome %v", claims["sub"])
}
```

## Explanation

The `keyfunc` passed to `jwt.Parse` returns `rsaPublicKey` unconditionally, without checking `token.Method`. `golang-jwt` lets the *token itself* declare which algorithm was used (via the `alg` header), and the library trusts whatever key the callback hands back for verifying against that declared algorithm. Because the callback never confirms the declared algorithm matches what the server expects (RSA), an attacker can submit a token with `alg: HS256` instead of `RS256`. The callback still returns `rsaPublicKey` — but now it gets used as an HMAC *secret* rather than an RSA public key. Since RSA public keys are, by design, non-secret (often published in a JWKS endpoint or embedded in client-side code), the attacker can compute a valid HMAC-SHA256 signature using that "secret," forge arbitrary claims (e.g. an admin `sub`), and have the forged token pass `token.Valid`. This is the classic JWT "algorithm confusion" variant of improper signature verification.

The fix has two parts, both necessary:

1. **Restrict accepted algorithms explicitly at parse time** with `jwt.WithValidMethods([]string{"RS256"})`. This makes the parser reject any token whose header does not declare exactly that algorithm before verification is even attempted.
2. **Assert the algorithm type inside the keyfunc itself** by checking `token.Method` is `*jwt.SigningMethodRSA`. This is defense in depth: the keyfunc is the last line of defense that decides *which key material to hand back*, and it must never hand back key material appropriate for one algorithm family when the token claims a different one.

Either control alone closes this specific bypass, but keeping both means the keyfunc remains safe even if it is later reused in a context where `WithValidMethods` is omitted.
