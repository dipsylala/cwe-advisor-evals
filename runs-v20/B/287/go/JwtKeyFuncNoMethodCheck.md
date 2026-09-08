## Verdict

exploitable

- cwe_id: CWE-287 (Improper Authentication)
- location: `JwtKeyFuncNoMethodCheck.go`, line 49 (`jwt.ParseWithClaims` call), sink introduced by the `keyFunc` at lines 44-46
- confidence: high

## Source

The `Authorization` header on the incoming HTTP request (`r.Header.Get("Authorization")`, line 33), with the `Bearer ` prefix stripped into `tokenString` (line 34). This is fully attacker-controlled, including the JOSE header's `alg` field, which `golang-jwt/jwt/v5` parses from the token before `keyFunc` runs.

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
		// keyFunc resolves the key used to verify the token's signature. It
		// asserts the token was actually signed with HMAC before returning the
		// secret, so a header claiming a different algorithm (e.g. "none" or an
		// RSA variant) is rejected instead of being verified against this key.
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return hmacSecret, nil
		}

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

The original `keyFunc` returned `hmacSecret` unconditionally, so an attacker could send a token whose JOSE header claims any algorithm the library supports and still have it verified against this HMAC secret - most seriously `alg: none`-adjacent confusion attacks or an RS256-to-HS256 downgrade (where a known RSA public key is fed back in as the HMAC secret), either of which lets an attacker forge a signature the server accepts. The fix adds an explicit type assertion on `token.Method` inside `keyFunc`, returning an error unless the token was signed with an `HMAC` method, and additionally passes `jwt.WithValidMethods([]string{"HS256"})` to `ParseWithClaims` so parsing is rejected before `keyFunc` is even invoked for a disallowed algorithm. Both checks come from the loaded `cwe/287/go` guidance for this exact bug class. `golang-jwt/jwt/v5` never accepts `alg: none` unless the caller opts in via `jwt.UnsafeAllowNoneSignatureType`, which this code does not do, so the residual risk closed here is specifically algorithm confusion/substitution, not none-alg bypass.

Library note: the code comment states it is written against `golang-jwt/jwt/v5.2.x`. The loaded guidance records the operative floor as v5.2.2 or later (CVE-2025-30204, excessive allocation while splitting a token header). This fix does not change `go.mod`; confirm the resolved version is >= v5.2.2 via SCA/dependency-check tooling before merging, and bump it in `go.mod`/`go.sum` if it is not.

## Behaviour changes

- `keyFunc` now returns an error for any token whose signing method is not `*jwt.SigningMethodHMAC` (e.g. RS256, ES256, or `none`), where before it silently accepted and attempted verification against `hmacSecret` for every method. This is the fix itself, not a side effect: only tokens actually signed with the service's own HMAC secret and algorithm now pass.
- `jwt.ParseWithClaims` gains a fourth argument, `jwt.WithValidMethods([]string{"HS256"})`. This narrows accepted algorithms to HS256 (the only one the service ever intends to issue, per the existing "signed with this service's HMAC secret" doc comment) and causes parsing to fail before `keyFunc` runs at all for any other `alg` value. No legitimate caller using this service's own token issuance is affected, since it only ever produces HS256 tokens.
- Added the standard-library `fmt` import, used only to construct the new error returned by `keyFunc`.
- No change to: token structure, claims handling, error responses (still `401` with the same message), context propagation, or any other line of the file.

Otherwise none - the fix leaves the sink's return value, error handling, and downstream `claims` usage exactly as before.

## Verification

Ran in a scratch Go module (outside the case directory) with the real dependency: `go mod init`, `go get github.com/golang-jwt/jwt/v5@v5.2.2`, `go mod tidy`, then `go vet ./...` and `go build ./...` against the fixed file - both completed with no output/errors, confirming the code compiles, `jwt.WithValidMethods` and `jwt.SigningMethodHMAC` are real v5 API surface, and no other caller in the file needed updating.

assumptions: none beyond the version-check note above (autonomous mode; no ambiguity in language or fix location - the SAST comment names the exact sink and the guidance names the exact fix pattern for it).
