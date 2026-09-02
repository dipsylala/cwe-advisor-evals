## Verdict
CONFIRMED

## Source
Line 21: `signedJWT.verify(new RSASSAVerifier(verificationKey));`

The code calls `verify()` on a `SignedJWT` object using Nimbus JOSE + JWT library, but fails to check the boolean return value indicating whether signature verification succeeded.

## Fix
```java
if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
    throw new SecurityException("JWT signature verification failed");
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

Replace the unguarded `verify()` call with a conditional check. Only proceed to extract and use JWT claims if `verify()` returns `true`. If verification fails, reject the token immediately.

## Explanation
The Nimbus JOSE + JWT library's `verify()` method returns a boolean: `true` if the cryptographic signature is valid, `false` if validation fails. The original code ignores this return value and proceeds to extract the username from the JWT claims unconditionally. An attacker can supply a JWT with an invalid signature, and the application will still trust its contents, completely bypassing the cryptographic protection intended by the signature.

The fix forces an explicit check of the return value before trusting any claims inside the JWT. If the signature does not verify, a `SecurityException` is thrown and the request is rejected.
