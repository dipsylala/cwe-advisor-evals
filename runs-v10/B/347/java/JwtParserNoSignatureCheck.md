## Verdict

Exploitable. The `SignedJWT.verify()` method returns a boolean indicating verification success, but the return value is not checked. The code continues to line 23 and trusts the JWT claims regardless of whether verification succeeded or failed, allowing an attacker to forge a token and impersonate any user.

## Source

Authorization header (line 15-16): `String authHeader = request.getHeader("Authorization")` and subsequent extraction of the token via `authHeader.substring("Bearer ".length())`.

## Fix

**Vulnerable code (line 18-24):**
```java
SignedJWT signedJWT = SignedJWT.parse(token);

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
signedJWT.verify(new RSASSAVerifier(verificationKey));

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

**Fixed code:**
```java
SignedJWT signedJWT = SignedJWT.parse(token);

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.getWriter().write("Unauthorized: Invalid JWT signature");
    return;
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

## Explanation

The `SignedJWT.verify()` method in Nimbus JOSE+JWT returns a boolean (true for valid signature, false for verification failure) rather than throwing an exception. The original code invoked `verify()` but discarded the return value, permitting execution to proceed with the token claims regardless of whether the signature was valid. The fix checks the boolean return value; when verification fails, the code now responds with HTTP 401 Unauthorized and terminates the handler before the claims are extracted. This prevents an attacker from forging a JWT and having it accepted by the application.

## Behaviour changes

The return value of `verify()` is now checked before proceeding. When verification fails, the method returns early with an HTTP 401 status and an error message, rather than continuing to extract and use the JWT claims. This is a security-critical behaviour change: only valid, authenticated tokens now proceed. No other contract is altered—the verified claims path retains the original logic of extracting the subject and writing a welcome message.
