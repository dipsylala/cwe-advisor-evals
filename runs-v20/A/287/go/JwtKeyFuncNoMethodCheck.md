## Verdict

Confirmed. `keyFunc` in `RequireBearerToken` returns the service's HMAC secret unconditionally, without checking `token.Method` against the algorithm the service actually signs with. `jwt.ParseWithClaims` derives the verification algorithm from the caller-supplied token header (`alg`) and calls `keyFunc` to obtain the corresponding key; when the key function does not pin the accepted method, an attacker can present a token whose header claims a different signing method than the one the service intends to trust, and the verification step ends up using attacker-influenced assumptions about how the signature should be checked rather than a check the server controls. This is the well-known JWT "algorithm confusion" failure mode and is a textbook instance of CWE-287 (Improper Authentication): the server is not actually authenticating that the token was produced with the key and algorithm it trusts, only that some signature validates under whatever method the token itself claims.

## Source

`r.Header.Get("Authorization")` at line 33 — the bearer token string is attacker-controlled input arriving on every request to a protected handler.

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
		// keyFunc resolves the key used to verify the token's signature. It first
		// confirms the token header actually claims the HMAC family this service
		// signs with, so a caller cannot swap in a different signing method (for
		// example an asymmetric algorithm, using this service's public material
		// or an attacker-chosen key as the "signature") and have it accepted.
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return hmacSecret, nil
		}

		token, err := jwt.ParseWithClaims(
			tokenString,
			claims,
			keyFunc,
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		)
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

Two independent layers now pin the algorithm before any key material is used to check a signature:

1. **`jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})`** — a parser option that makes `jwt.ParseWithClaims` reject any token whose header `alg` is not exactly `HS256`, before the signature is verified. This is `golang-jwt/jwt/v5`'s documented mechanism for constraining acceptable algorithms and is the primary defense: the server, not the token, decides which algorithm is acceptable.
2. **The `keyFunc` type check** (`token.Method.(*jwt.SigningMethodHMAC)`) — a second, defense-in-depth check at the point the key is handed back, so that if this `keyFunc` is ever reused or the parser option is dropped in a future edit, the key is still never returned for a non-HMAC method.

Together these close the algorithm-confusion gap: the previous code let the token's own header dictate which `jwt.SigningMethod` implementation was invoked for verification while `keyFunc` handed back the same static secret regardless of what that header claimed. `token.Valid` was consequently a statement about "some signing method the token itself named accepted this secret," not "this service's chosen algorithm verified this secret," which is the improper-authentication gap CWE-287 flags. The fix makes the accepted algorithm a value the server fixes ahead of time, independent of anything in the incoming request.

No other behavior changes: the secret, claims type, error responses, and context propagation are unchanged, so legitimate `HS256`-signed tokens continue to validate exactly as before.
