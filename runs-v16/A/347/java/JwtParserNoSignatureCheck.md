## Verdict

The code calls `signedJWT.verify()` but ignores the boolean return value. The Nimbus JOSE library's `verify()` method returns `true` only when the cryptographic signature is valid; a `false` return indicates verification failed. By not checking this result, the code accepts invalid or tampered JWTs, completely bypassing the signature verification intended to authenticate the token.

## Source

```java
SignedJWT signedJWT = SignedJWT.parse(token);

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
signedJWT.verify(new RSASSAVerifier(verificationKey));

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

## Fix

Check the boolean return value of `verify()` and halt processing if verification fails:

```java
SignedJWT signedJWT = SignedJWT.parse(token);

if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT signature verification failed");
    return;
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

## Explanation

CWE-347 occurs when a cryptographic signature is computed or verified but the result is not properly acted upon. In this case, the Nimbus JOSE library provides signature verification through `SignedJWT.verify()`, which returns a boolean: `true` if the signature is valid and authentic, `false` if verification fails.

The vulnerable code ignores this return value. An attacker can supply a JWT with an invalid, forged, or completely missing signature, and the code will still extract and use claims from it. This defeats the entire purpose of signature verification, which is to authenticate the token's origin and detect tampering.

The fix checks the return value explicitly. If `verify()` returns `false`, the request is rejected immediately with an HTTP 401 Unauthorized response. Only when verification succeeds (`true`) does the code proceed to extract and use the claimed identity. This ensures that every JWT used in the application has been cryptographically validated against the expected key.
