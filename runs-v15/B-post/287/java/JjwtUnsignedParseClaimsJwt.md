## Verdict

Exploitable. The Authorization header provides an attacker-controlled JWT token that is parsed without signature verification, allowing an attacker to forge authentication claims.

## Source

Untrusted source: `Authorization` HTTP header value. Extracted on line 55 as `token = header.substring(BEARER_PREFIX.length())` from a user-supplied request header.

## Fix

**Vulnerable code (lines 57–58):**

```java
// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
Jwt<?, Claims> jwt = Jwts.parser().parseClaimsJwt(token);
```

**Fixed code:**

```java
SecretKey signingKey = /* load from secure configuration, e.g., application.properties or a key store */;
Jwt<?, Claims> jwt = Jwts.parser()
    .setSigningKey(signingKey)
    .parseClaimsJws(token);
```

The vulnerable method `parseClaimsJwt()` accepts unsigned JWTs (with `alg: none`) without verifying a signature. The fix replaces it with `parseClaimsJws()` (the signed variant) and binds it to a server-controlled signing key via `setSigningKey()`. Now the JWT must carry a valid signature matching the server's key; unsigned tokens and tokens with mismatched algorithms are rejected.

For jjwt 0.11.5, the signing key should be a `javax.crypto.SecretKey` generated with sufficient entropy (e.g., `Jwts.SIG.HS256.key().build()`) and loaded from secure configuration or a key store, never hardcoded.

## Explanation

The vulnerability occurs because `parseClaimsJwt()` is the unsigned-only parser and never checks a signature. An attacker can craft a JWT with `alg: none` or `alg: unsigned`, set arbitrary claims (including `sub` to impersonate any user), and authenticate without needing the server's signing key. This violates the authentication model: identity claims must come from a cryptographically verified token, not from a client-supplied value.

The fix enforces that model by requiring a valid signature. By switching to `parseClaimsJws()` (the signed variant) and binding it to the server's signing key, the parser now rejects any token whose signature does not match. The signature can only be produced if the attacker knows the key, which is server-controlled and never transmitted to the client. Token tampering is detectable; forged identity claims are rejected at parse time before any claims are used.

The signing key must be loaded from secure configuration or a key store (e.g., environment variables, application properties, or AWS Secrets Manager) rather than hardcoded to allow rotation and to keep the key out of source control.

## Behaviour changes

- **Signing key addition:** A cryptographic key is now required and passed to the parser. This is a new dependency on configuration (e.g., a Spring-injected `SecretKey` or a key loaded at startup from a secret store).
- **Algorithm enforcement:** Tokens with `alg: none`, unsigned tokens, or tokens signed with a different algorithm are rejected. Only tokens signed with the same key-algorithm pair that `setSigningKey()` expects are accepted.
- **Signature validation:** The parser now verifies the signature before returning the claims. Tampered tokens are rejected with a `SignatureException` or similar; the application should catch this and return a 401.
- **Error handling:** The parse call may now throw `SignatureException`, `MalformedJwtException`, or `UnsupportedJwtException` where the original succeeded. The filter should be updated to catch these and reject the request with a 401 response rather than proceeding with an invalid token.

No other behaviour changes. The return type and the subsequent claim extraction remain the same.
