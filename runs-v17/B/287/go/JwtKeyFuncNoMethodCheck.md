## Verdict

Confirmed. The `keyFunc` callback at line 44-46 does not validate the signing method before returning the HMAC secret, allowing algorithm-confusion attacks. An attacker can submit a token with `alg: none` or switch to a different algorithm and forge a valid signature.

## Source

**File**: E:/Github/cwe-advisor/evals/cases/287/go/JwtKeyFuncNoMethodCheck/JwtKeyFuncNoMethodCheck.go  
**Line**: 49  
**Vulnerable code**:

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
	return hmacSecret, nil
}

token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
```

The `keyFunc` ignores the `token.Method` field and returns the HMAC secret unconditionally. This means the parser trusts the `alg` header from the token itself to determine which algorithm to use for signature verification. An attacker can set `alg: none` to skip signature verification entirely, or use a different algorithm (e.g., HS256 with the public key as the secret in an asymmetric-to-symmetric confusion attack).

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
		// keyFunc resolves the key used to verify the token's signature.
		// It validates that the signing method is HMAC before returning the key,
		// preventing algorithm-confusion attacks where an attacker switches
		// the header to alg: none or another algorithm.
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return hmacSecret, nil
		}

		// Parse the token with the HMAC method check and restrict to HS256
		token, err := jwt.ParseWithClaims(
			tokenString,
			claims,
			keyFunc,
			jwt.WithValidMethods([]string{"HS256"}),
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

The fix adds two layers of defence against algorithm-confusion attacks:

1. **Type assertion in `keyFunc`**: The `keyFunc` now checks that `token.Method` is an instance of `jwt.SigningMethodHMAC` before returning the key. If the attacker submits a token with a different algorithm (including `none`), the function returns an error and parsing fails immediately. This check is the primary defence because it rejects unauthorized algorithms at the point where the key is resolved.

2. **Parser-level allowlist**: The `jwt.WithValidMethods([]string{"HS256"})` option restricts the parser to accept only HS256 tokens. This provides defence-in-depth: even if the `keyFunc` check is somehow bypassed, the parser itself will reject any token that claims a different algorithm. This option is available in golang-jwt/jwt/v5.

The fix also adds the `fmt` import needed for the error message. The key change is in the `keyFunc` callback: it now rejects any signing method other than HMAC, closing the algorithm-confusion vector entirely. The parser now trusts only tokens signed with HS256 and rejects `alg: none`, `alg: RS256`, and any other algorithm an attacker might submit.

## Behaviour changes

**Before**: The middleware accepted bearer tokens signed with any algorithm, as long as they could be verified with the HMAC secret. An attacker could forge authentication by submitting a token with `alg: none` (no signature required), or by exploiting other algorithm-confusion vectors.

**After**: The middleware now rejects any token that is not signed with HS256. The parser returns `UnexpectedSigningMethodError` if the token claims a different algorithm. This includes:
- Tokens with `alg: none` (rejected by both the `keyFunc` check and the parser allowlist)
- Tokens with `alg: RS256` or any other asymmetric algorithm (rejected by the `keyFunc` check)
- Tokens with `alg: HS512` or any non-HS256 symmetric algorithm (rejected by the parser allowlist)

Legitimate requests using correctly signed HS256 bearer tokens are unaffected. The API's response to invalid tokens remains unchanged: a 401 Unauthorized with "invalid bearer token".

**Verification**: Compiled with `go vet` with no errors. The fix applies the exact pattern recommended in the CWE-287 Go guidance.
