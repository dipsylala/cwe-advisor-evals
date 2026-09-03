## Verdict

CWE-347 confirmed. The `keyfunc` callback on line 15-17 returns the RSA public key without first validating `token.Method`, allowing an attacker to switch the signing algorithm from RS256 to HS256 and forge a signature using the public key as an HMAC secret.

## Source

File: `evals/cases/347/go/JwtParseUnverified/JwtParseUnverified.go`, lines 15-20

```go
keyfunc := func(token *jwt.Token) (interface{}, error) {
	return rsaPublicKey, nil
}

token, err := jwt.Parse(tokenString, keyfunc)
```

The keyfunc does not check `token.Method` before returning the key material, enabling algorithm confusion.

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
		// Validate the signing method is RSA before returning key material
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	// Add defense-in-depth: restrict to RS256 at parse time
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

The fix adds two layers of verification:

1. **Keyfunc type assertion** (line 17-19): Before returning the public key, assert that `token.Method` is of type `*jwt.SigningMethodRSA`. If the attacker attempts to switch to HS256, this type assertion fails and returns an error, preventing the algorithm confusion attack.

2. **Parser option (line 25)**: Pass `jwt.WithValidMethods([]string{"RS256"})` to `jwt.Parse()` as defense in depth. This ensures the parser itself rejects any algorithm other than RS256, even if the keyfunc is modified in the future.

The existing `token.Valid` check (line 26) continues to validate the signature itself after the algorithm is confirmed.

## Behaviour changes

- **Before**: Accepts tokens with any signing algorithm and verifies them using `rsaPublicKey` as the key material. An attacker can forge an HS256 token using the public key as the HMAC secret, and the parser will accept it because signature verification passes.

- **After**: Enforces RS256 at two checkpoints. Attempts to use any other algorithm (including HS256 with the public key) are rejected with an error. The token is only validated if both the algorithm matches and the signature is cryptographically correct.
