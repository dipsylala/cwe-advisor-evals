## Verdict

Real. The keyFunc callback accepts the token without verifying its claimed signing algorithm, allowing an attacker to forge authentication by submitting a token with an unexpected algorithm (e.g., "none" or an asymmetric algorithm).

## Source

Line 49: `token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)`

The vulnerability is in the keyFunc definition (lines 44–46). It returns the HMAC secret for any token regardless of its `Method` field, which claims the signing algorithm. A keyFunc must validate that the token's claimed algorithm matches the server's expectations before providing the key.

## Fix

Add an algorithm check in the keyFunc:

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return hmacSecret, nil
}
```

Alternatively, be explicit about the expected algorithm:

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
	if token.Method.Alg() != "HS256" {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return hmacSecret, nil
}
```

Both approaches reject tokens claiming to be signed with algorithms other than HMAC (e.g., RS256, "none", or any asymmetric method).

## Explanation

When a keyFunc does not validate the token's algorithm before providing the signing key, an attacker can manipulate the token header to claim a different algorithm was used. Even if the attacker does not possess the actual key for that algorithm, a keyFunc that returns the same key regardless allows the JWT library to proceed with verification using the wrong algorithm, potentially bypassing authentication.

The first fix checks that the token's method is an HMAC variant; this is sufficient if only HMAC algorithms are in scope. The second is more explicit and rejects anything but the exact algorithm the service uses. Both prevent algorithm confusion attacks and ensure that the signing key is only used to verify tokens that claim to have been signed with HMAC.

Add `import "fmt"` if not already present.
