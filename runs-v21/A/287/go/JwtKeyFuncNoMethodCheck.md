## Verdict
CONFIRMED: CWE-287 (Improper Authentication) - Algorithm substitution attack via unsigned keyFunc.

## Source
The `keyFunc` closure at lines 44-46 accepts tokens regardless of their claimed signing method. An attacker can claim a token uses RS256 (asymmetric) while providing an HMAC-signed token, bypassing authentication.

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
		// keyFunc resolves the key used to verify the token's signature. It validates
		// that the token uses the expected HMAC signing method before returning the secret.
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method to prevent algorithm substitution attacks.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return hmacSecret, nil
		}

		token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
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
The vulnerability exploited algorithm substitution. The original `keyFunc` trusted the token's claimed signing method without validation, allowing attackers to present tokens as RS256-signed while only possessing the HMAC secret.

The fix adds a type assertion checking that `token.Method` is `*jwt.SigningMethodHMAC`. If the token claims any other algorithm (RS256, ES256, or any non-HMAC variant), the keyFunc returns an error instead of the secret. This forces jwt.ParseWithClaims to reject the token during validation.

The check happens before the key is returned, preventing the verification to proceed with a mismatched algorithm, closing the algorithm substitution attack path.
