## Verdict

The keyfunc callback lacks algorithm validation, enabling an algorithm confusion attack where an attacker can switch a token from RS256 (RSA signature) to HS256 (HMAC) and forge a signature using the server's RSA public key treated as an HMAC secret.

## Source

The vulnerability originates from an attacker-controlled JWT token passed via the `Authorization` header (`r.Header.Get("Authorization")`). The token includes a malicious `alg` claim that the keyfunc does not validate.

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
		// Validate the algorithm is RSA before returning key material
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	// Use WithValidMethods for defense in depth
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

The fix adds two layers of validation to prevent algorithm confusion:

1. **Keyfunc type assertion** - Inside the `Keyfunc` callback, assert that `token.Method` is the concrete type `*jwt.SigningMethodRSA` before returning the key material. An attacker cannot substitute HS256 because the type assertion will fail if the method is not RSA-based.

2. **Parser option for defense in depth** - Pass `jwt.WithValidMethods([]string{"RS256"})` to the `Parse()` call. This restricts accepted algorithms at the parser level and provides protection against future keyfunc changes.

Together, these prevent the algorithm confusion attack described in the golang-jwt library's security documentation, where an attacker switches a legitimately signed RS256 token to HS256 and uses the public RSA key as an HMAC secret.

## Behaviour changes

- **Error handling** - When a token with a non-RSA signing method is presented (e.g., HS256, ECDSA, or "none"), the keyfunc now returns an error instead of silently accepting it. This causes `jwt.Parse()` to set `token.Valid = false`, triggering the existing error case on line 22.
- **Authorization behavior** - Tokens with non-RS256 algorithms are now rejected with HTTP 401 Unauthorized, the same response as invalid signatures or parsing errors.
- **No false negatives** - Valid RS256 tokens that previously would have been accepted are still accepted. The fix closes the algorithm substitution gap without changing behavior for legitimate requests.
