## Verdict

Exploitable. The keyfunc at line 15-17 returns the RSA public key without validating the token's signing algorithm. An attacker can forge a token, sign it with HS256 using the server's RSA public key (which is public) as an HMAC secret, and bypass signature verification. The vulnerability is confirmed as algorithm confusion (CWE-347).

## Source

The data flow originates at line 13 with untrusted input from the HTTP Authorization header:
```
tokenString := r.Header.Get("Authorization")
```

This untrusted token reaches the sink at line 20:
```
token, err := jwt.Parse(tokenString, keyfunc)
```

The keyfunc (lines 15-17) does not validate the algorithm before returning the verification key, enabling algorithm confusion.

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
		// Verify the algorithm is RS256, not HS256 or another algorithm
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	// Parse with algorithm validation as defense in depth
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

The fix closes the algorithm confusion attack by adding two layers of validation. First, inside the keyfunc at line 18-20, a type assertion checks that the token's signing method is specifically `*jwt.SigningMethodRSA` (RS256). If the attacker switches the algorithm header to HS256, the type assertion fails and the keyfunc returns an error before returning any key material. Second, the parser call at line 24 now includes `jwt.WithValidMethods([]string{"RS256"})`, which provides defense-in-depth by restricting the parser itself to only accept RS256 tokens. This dual validation prevents an attacker from forging a token with HS256 and having the server sign it with the public key as an HMAC secret. The existing error check at line 25 correctly handles both sources of errors: the keyfunc rejection and any other parse errors.

## Behaviour changes

- **Added algorithm check in keyfunc (lines 18-20)**: The keyfunc now type-asserts `token.Method` against `*jwt.SigningMethodRSA` and returns an error if the token uses any other algorithm. This is a security hardening measure that prevents algorithm confusion.
- **Added `jwt.WithValidMethods` option (line 24)**: The `jwt.Parse()` call now includes `jwt.WithValidMethods([]string{"RS256"})` as a parser option. This instructs the parser to reject any token with an algorithm header other than RS256, providing defense-in-depth validation at the parser level.
- **No other behavioural changes**: The error handling, return values, and claim extraction remain identical. Tokens with valid RS256 signatures continue to be accepted; tokens with invalid or missing signatures, or with mismatched algorithms, are now correctly rejected.
