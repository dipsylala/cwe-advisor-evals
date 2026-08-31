## Verdict
CONFIRMED — CWE-347 (Improper Verification of Cryptographic Signature)

## Source
The `authMiddleware` function at line 12 receives a JWT token from the HTTP `Authorization` header without validating the signing algorithm. The keyfunc at line 15 returns the public key unconditionally, allowing an attacker to forge a token using a different algorithm (e.g., "none" or HS256 with a known value) and bypass signature verification.

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
		// Validate that the token uses RSA signing, not a weaker or unverified algorithm
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, keyfunc)
	if err != nil || !token.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "welcome %v", claims["sub"])
}
```

## Explanation
The vulnerability exists because the keyfunc does not validate the algorithm declared in the token's header. An attacker can craft a token with `"alg": "none"` or switch to a symmetric algorithm like HS256, and if the signature verification logic trusts the algorithm field, the attacker can forge a valid signature.

The fix adds an algorithm check in the keyfunc: it asserts that the token uses an RSA algorithm and rejects any other method with an explicit error. This prevents algorithm confusion attacks and ensures only tokens signed with RSA (and verified with the corresponding public key) are accepted.

Additionally, `ParseWithClaims` is used instead of `Parse` for better type safety with the claims extraction.
