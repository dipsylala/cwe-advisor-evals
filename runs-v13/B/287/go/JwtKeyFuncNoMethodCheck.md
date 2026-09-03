## Verdict
CONFIRMED: The `keyFunc` callback passed to `jwt.ParseWithClaims` does not validate the token's signing method before returning the HMAC secret. This allows algorithm-confusion attacks where an attacker can submit a token with `alg: none`, or switch from HS256 to RS256 and reuse the server's public key as an HMAC secret to forge a valid signature.

## Source
The vulnerability is at line 49 in the `jwt.ParseWithClaims` call, combined with the unsafe `keyFunc` implementation on lines 44-46. The `keyFunc` unconditionally returns `hmacSecret` without asserting that `token.Method` is the expected `SigningMethodHMAC` type:

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
    return hmacSecret, nil
}

token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
```

The attacker-controlled `alg` header in the JWT token decides which signing method the library uses for verification, and without a method check in `keyFunc`, the same secret is returned for any claimed algorithm.

## Fix
Add an explicit assertion of `token.Method` inside `keyFunc` to reject any signing algorithm other than HMAC, and add `jwt.WithValidMethods` to the parser for defense-in-depth:

```go
import (
    "context"
    "fmt"
    "net/http"
    "strings"

    "github.com/golang-jwt/jwt/v5"
)

// ... (Claims and context key unchanged)

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
            // Assert the signing method is HMAC before returning the key
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return hmacSecret, nil
        }

        // Use WithValidMethods to reject non-HMAC algorithms before keyFunc is called
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
The fix prevents algorithm-confusion attacks by enforcing that the token's signing method must be `SigningMethodHMAC` before accepting the key. The type assertion `token.Method.(*jwt.SigningMethodHMAC)` fails if the attacker claims `alg: none`, `alg: RS256`, or any other non-HMAC method, returning an error instead of a key. The `jwt.WithValidMethods([]string{"HS256"})` parser option provides a second layer by rejecting any token with a disallowed algorithm header before the key function is even invoked. Together, these changes ensure only HS256-signed tokens are accepted, closing the CWE-287 bypass where an attacker could forge a valid-looking signature by switching algorithms.

## Behaviour changes
- Tokens with `alg: none`, `alg: RS256`, or any algorithm other than HS256 are now rejected with an error.
- Unauthenticated requests receive `401 Unauthorized` with "invalid bearer token" as before, but now based on enforced method validation rather than accepting any algorithm.
- The error log will include the attacker-supplied `alg` header value for security monitoring and incident response.
- Performance impact is negligible: one type assertion per token verification, well below typical latency.
- Legitimate clients using HS256 are unaffected.
