## Verdict

The finding is valid and exploitable. The code calls `SignedJWT.verify()` but ignores its boolean return value, accepting JWT tokens regardless of whether their signatures are valid or forged.

## Source

The HTTP `Authorization` header (line 15) provides attacker-controlled input: `String authHeader = request.getHeader("Authorization");`

This token is parsed and used without proper signature verification.

## Fix

Check the return value of `signedJWT.verify()` and reject the request if verification fails:

```java
if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
    throw new SignatureException("JWT signature verification failed");
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

Alternatively, if `SignatureException` is already declared in the method signature or caught by the calling code:

```java
boolean isValid = signedJWT.verify(new RSASSAVerifier(verificationKey));
if (!isValid) {
    throw new SignatureException("JWT signature verification failed");
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

Replace the import if needed:
```java
import com.nimbusds.jose.JOSEException;
// or
import java.security.SignatureException;
```

## Explanation

The `SignedJWT.verify()` method in Nimbus JOSE+JWT returns a boolean: `true` if the RSA signature is valid, `false` if verification fails. The current code ignores this return value entirely, so an attacker can provide a JWT signed with any key (or unsigned), and the application will accept it as valid.

The fix adds an explicit check of the return value. If verification fails, an exception is thrown immediately, preventing the forged token from being accepted. This ensures that only tokens with valid signatures are processed further.

The fix preserves the existing verification algorithm and key type - it only adds the missing validation of the verification result. The strong-typed use of `RSASSAVerifier` with the configured `verificationKey` already prevents algorithm confusion attacks (pin the key type).

## Behaviour changes

- **Before**: Any JWT token was accepted, including forged ones with invalid signatures.
- **After**: Only JWTs with valid RSA signatures matching `verificationKey` are accepted. Requests with unsigned or incorrectly-signed tokens are rejected with a `SignatureException`.
- **No regression**: The fix does not change the normal flow when a valid signature is presented. It only adds rejection of the previously-accepted invalid case.
