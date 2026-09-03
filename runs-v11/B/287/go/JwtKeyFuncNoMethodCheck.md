## Verdict

CONFIRMED: The `keyFunc` passed to `jwt.ParseWithClaims` does not validate the signing method, allowing an attacker to forge authentication tokens via algorithm confusion or `alg: none` attacks.

## Source

**File**: `JwtKeyFuncNoMethodCheck.go`  
**Line**: 49  
**Sink**: `jwt.ParseWithClaims(tokenString, claims, keyFunc)`

The vulnerable `keyFunc` (lines 44–46):
```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
    return hmacSecret, nil
}
```

## Fix

Add a type assertion inside `keyFunc` to validate only HMAC is accepted, and use `jwt.WithValidMethods()` on the parser for defense-in-depth. Import `fmt` if not present.

**Fixed code**:
```go
import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ... existing code ...

func RequireBearerToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader || tokenString == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			// Validate signing method: reject anything other than HMAC.
			// Without this check, an attacker can change the alg header to
			// none or RS256 and forge a valid-looking signature.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return hmacSecret, nil
		}

		// ParseWithClaims with method validation.
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

The fix adds two layers of defence. First, `keyFunc` now asserts that `token.Method` is a `jwt.SigningMethodHMAC`, rejecting any other algorithm (including `none`). This prevents the attacker-controlled `alg` header from dictating how the token is verified. Second, `jwt.WithValidMethods([]string{"HS256"})` on the parser rejects the token before even calling `keyFunc` if a disallowed algorithm is named in the header. Together, these ensure that a forged or tampered token with a different signing method is rejected before any claims are trusted. The error message names the unexpected algorithm for audit logging.

## Behaviour changes

- Tokens signed with anything other than HS256/HMAC are now rejected at parsing time with an error (previously would have been accepted and marked valid).
- Failed authentication still returns HTTP 401 as before.
- No changes to successful authentication flow; valid HS256-signed tokens pass validation exactly as before.
