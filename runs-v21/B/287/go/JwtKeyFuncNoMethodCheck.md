## Verdict
CONFIRMED: The `keyFunc` callback passed to `jwt.ParseWithClaims` on line 49 returns the HMAC signing secret without verifying that the token's `alg` header specifies HMAC. This permits algorithm-confusion attacks where an attacker submits a token with `alg: none` or switches from HS256 to RS256, and the function returns the known key regardless. The vulnerability is in lines 44-46.

## Source
The vulnerable pattern is the `keyFunc` closure:
```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
    return hmacSecret, nil
}
```

This function is called by `jwt.ParseWithClaims` during token verification. It should verify that the token's signing method matches the expected HMAC algorithm before returning the key. Without this check, the attacker-controlled `alg` header in the token determines which algorithm is used to verify the signature, not the application's configuration.

## Fix

### File: JwtKeyFuncNoMethodCheck.go
```go
// Package auth implements bearer token authentication middleware for internal API handlers.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// hmacSecret is the shared HMAC signing key configured for this service. In
// production it is loaded from the AUTH_HMAC_SECRET environment variable at
// startup rather than hardcoded here.
var hmacSecret = []byte("change-me-in-production-32-byte-secret-key")

// Claims carries the identity fields this service expects inside a bearer token.
type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type contextKey string

const claimsContextKey contextKey = "claims"

// RequireBearerToken wraps a protected handler and verifies the Authorization
// header carries a bearer token signed with this service's HMAC secret. Written
// against golang-jwt/jwt/v5.2.x.
func RequireBearerToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader || tokenString == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		// keyFunc resolves the key used to verify the token's signature. It now
		// asserts that the token uses HMAC signing before returning the key,
		// preventing algorithm-confusion attacks.
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			// Verify the token claims to use HMAC signing, not alg:none or RS256
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return hmacSecret, nil
		}

		// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
		token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
		if err != nil || !token.Valid {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

## Explanation
The fix adds two layers of defence:

1. **Algorithm assertion in keyFunc** (line 56-59): Before returning the HMAC secret, the function now type-asserts that `token.Method` is `*jwt.SigningMethodHMAC`. If the attacker supplies a token with `alg: none` or `alg: RS256`, this assertion fails and `keyFunc` returns an error instead of the key. This prevents the parser from accepting a token signed with a different algorithm.

2. **WithValidMethods parser option** (line 62): The `jwt.WithValidMethods([]string{"HS256"})` option provides a second layer of defence. It restricts the parser to only accept the HS256 algorithm, so parsing fails before even calling `keyFunc` if the token header claims a different algorithm. This implements the defence-in-depth principle recommended in the CWE-287 Go guidance.

3. **fmt import** (line 7): Added to support formatted error messages in the `keyFunc` return statement.

The fix eliminates the algorithm-confusion vulnerability by pinning the signing method server-side, so the attacker-controlled `alg` header no longer influences how the token is verified.

## Behaviour changes
- **Tokens with non-HMAC algorithms are rejected**: Any token claiming `alg: none`, `alg: RS256`, `alg: ES256`, or any algorithm other than `HS256` will now be rejected with an error before validation. This is correct security behaviour - the application only trusts HMAC-signed tokens.
- **Error message includes claimed algorithm**: When a token with an unexpected algorithm is submitted, the error message now includes the attacker-supplied algorithm value for logging and debugging.
- **Parser catches algorithm mismatches twice**: The `WithValidMethods` option in the parser provides early rejection, and the `keyFunc` check provides a fallback. If either fails, the token is rejected.
