## Verdict
CONFIRMED — CWE-347 improper verification of cryptographic signature. The keyfunc does not validate the signing algorithm, allowing algorithm confusion attacks.

## Source
The vulnerability is in the keyfunc at lines 15-17, which accepts any algorithm. An attacker can send a token signed with HS256 (HMAC) instead of RSA and use the public key as the HMAC secret to forge a signature.

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
		// Validate the signing method is RSA to prevent algorithm confusion attacks
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
	token, err := jwt.Parse(tokenString, keyfunc)
	if err != nil || !token.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "welcome %v", claims["sub"])
}
```

## Explanation
The fix adds algorithm validation in the keyfunc callback. Before returning the public key, it checks that the token was signed with RSA (not HMAC or another algorithm). This prevents algorithm confusion attacks where an attacker could craft an HS256-signed token using the public key as the HMAC secret. The type assertion `token.Method.(*jwt.SigningMethodRSA)` ensures only RSA algorithms are accepted; any other algorithm causes Parse to fail with the returned error.
