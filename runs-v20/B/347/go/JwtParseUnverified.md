## Verdict

Confirmed. `jwt.Parse` at line 20 is fed a `Keyfunc` that returns `rsaPublicKey` unconditionally, without checking `token.Method` (or `token.Header["alg"]`). This is the golang-jwt algorithm-confusion gap: an attacker can take a token whose header claims `alg: HS256`, and the library will call the keyfunc, receive the RSA public key back, and verify the HMAC signature using that public key's bytes as the HMAC secret. Because the RSA public key is not secret (it is server config, typically distributable), the attacker can compute a valid HMAC over an arbitrary payload and forge a token that `jwt.Parse` accepts as `token.Valid == true`. This is improper verification of the token's cryptographic signature: the code trusts a signature the keyfunc never confirmed was produced with the expected algorithm/key type.

## Source

`r.Header.Get("Authorization")` (line 13) - the raw, attacker-controlled `Authorization` header, including its embedded JWT header (`alg`) and signature - flows unchanged into `jwt.Parse(tokenString, keyfunc)` at line 20.

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
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	}

	token, err := jwt.Parse(
		tokenString,
		keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "welcome %v", claims["sub"])
}
```

## Explanation

The keyfunc now asserts `token.Method` against the concrete `*jwt.SigningMethodRSA` type before returning key material, and returns an error for anything else - so a token whose header claims `HS256` (or any non-RSA method) is rejected before the RSA public key is ever handed back as verification material, closing the algorithm-confusion path. `jwt.WithValidMethods([]string{"RS256"})` is added as a parser-level defense in depth, restricting acceptable algorithms independently of the keyfunc so a future keyfunc edit can't reopen the gap alone. `jwt.WithExpirationRequired()` is added because golang-jwt only validates `exp` when the claim is present and does not require it by default - without this option a token minted with no `exp` claim would pass as unexpired forever, which is a second, related verification gap the same sink contract exposes. All three additions are parser-side (`Keyfunc` and `ParserOption`s); the call's return value (`*jwt.Token, error`), the `err`/`token.Valid` check, and the claims-reading logic are unchanged, so the sink's existing contract (return shape, failure-to-401 behavior) is preserved.

## Behaviour changes

- A token signed with any algorithm other than RS256 (e.g., a forged HS256 token using the RSA public key as an HMAC secret, or a `none`-algorithm token) is now rejected with 401, where it was previously either rejected only by luck (mismatched key-type error) or, in the vulnerable case, accepted as valid.
- A legitimately RS256-signed token that omits the `exp` claim is now rejected with 401 (`WithExpirationRequired`); previously it would have been treated as valid with no expiration. Any legitimate issuer already including `exp` (the normal case) is unaffected.
- No change to the response body, status codes used, claims extraction, or the `rsaPublicKey` variable's source/type.

Checks performed: `go vet ./...` and `go build ./...` against the fixed file in a scratch module pinned to `github.com/golang-jwt/jwt/v5 v5.3.1` (matching the case's import path) - both passed with no diagnostics, confirming `jwt.SigningMethodRSA`, `jwt.WithValidMethods`, and `jwt.WithExpirationRequired` all exist and are used with correct signatures in this version.
