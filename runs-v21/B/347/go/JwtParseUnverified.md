## Verdict

**CONFIRMED** – CWE-347: Improper Verification of Cryptographic Signature

## Source

The vulnerability is in the `authMiddleware` function at line 20 (`jwt.Parse` call). The `keyfunc` closure (lines 15-17) does not validate the signing algorithm before returning key material, enabling algorithm confusion. An attacker can take a legitimate RS256 token, re-sign it as HS256 using the server's RSA public key as an HMAC secret, and bypass signature verification.

Data flow:
- Attacker supplies a crafted JWT token in the Authorization header
- Keyfunc receives token without checking `token.Method`
- Keyfunc returns `rsaPublicKey` for any algorithm (including HS256)
- Parser accepts HS256 token signed with public key as HMAC secret
- Authentication is bypassed

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
		// Verify the algorithm is RS256, not HS256 or other
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	// Parse with algorithm restriction as defense in depth
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

The fix closes CWE-347 by adding two layers of algorithm validation:

1. **Keyfunc Method Check** (line 18-21): Before returning the RSA public key, the keyfunc now type-asserts `token.Method` against `*jwt.SigningMethodRSA`. If the token claims any other algorithm (such as HS256), the function returns an error immediately, preventing key material from being released to an algorithm mismatch. This blocks the core algorithm-confusion attack where an HS256 signature would be verified using the returned key.

2. **Parser Algorithm Allowlist** (line 24): The `jwt.WithValidMethods([]string{"RS256"})` option is added to `jwt.Parse()` as defense in depth. This ensures the parser itself validates that only RS256 tokens are accepted, even if a future keyfunc change accidentally removes the method check. The parser will reject any token with a different algorithm in its header.

These changes enforce that only RS256-signed tokens with valid signatures can pass verification. An attacker who attempts to re-sign a token as HS256 using the public key as a secret will now be rejected at both the keyfunc and parser levels.

## Behaviour changes

- **Error return on algorithm mismatch**: The keyfunc now returns a non-nil error when `token.Method` is not `*jwt.SigningMethodRSA`. This causes `jwt.Parse()` to return an error and sets `token.Valid = false`, triggering the 401 response at line 25. Previously, HS256 tokens would have passed verification.
- **Parser-level enforcement**: The `WithValidMethods` option adds a second validation gate. Even if the token passes the keyfunc, it must declare RS256 in its header or be rejected.
- **No change to success path**: Legitimate RS256 tokens with valid signatures continue to parse successfully and reach the claims extraction at line 28. The error handling and response logic remain unchanged.
