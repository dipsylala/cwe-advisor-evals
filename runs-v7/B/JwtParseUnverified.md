## Verdict

Algorithm confusion vulnerability in JWT verification. The keyfunc does not validate the signing method before returning the key, allowing an attacker to switch from RS256 to HS256 and sign with the RSA public key as an HMAC secret, bypassing authentication.

## Source

Line 13: `tokenString := r.Header.Get("Authorization")` — attacker-controlled JWT

Line 20: `token, err := jwt.Parse(tokenString, keyfunc)` — vulnerable sink with missing algorithm check in keyfunc

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
		// FIXED: Type-assert token.Method to ensure RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	// FIXED: Add jwt.WithValidMethods for defense in depth
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.MapClaims{},
		keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "welcome %v", claims["sub"])
}
```

## Explanation

The vulnerability exists because the keyfunc returns the RSA public key without checking that the token's signing method is actually RSA (RS256). An attacker can forge a token using RS256, but then modify the header to claim HS256, and since the keyfunc doesn't validate the method, it returns the RSA public key which is then used as an HMAC secret. HMAC validation with the public key succeeds, and the forged token is accepted.

The fix adds two layers of defense:

1. **Type assertion in keyfunc**: Before returning key material, assert that `token.Method` is `*jwt.SigningMethodRSA`. Any other method (including HS256) is rejected immediately with an error.

2. **`jwt.WithValidMethods()` option**: Defense in depth. The parser now rejects any token claiming an algorithm outside the allowlist, even if the keyfunc were to be bypassed in the future.

3. **`jwt.WithExpirationRequired()`**: Additional hardening per language guidance to ensure tokens without `exp` claim are rejected.

The code also switches from `jwt.Parse()` to `jwt.ParseWithClaims()` to explicitly set validation options.

## Behaviour changes

- Tokens with HS256 or any algorithm other than RS256 are now rejected with an error instead of being accepted.
- Tokens without an `exp` claim are now rejected.
- Parser options provide explicit, declarative algorithm validation that survives future code changes to the keyfunc.
