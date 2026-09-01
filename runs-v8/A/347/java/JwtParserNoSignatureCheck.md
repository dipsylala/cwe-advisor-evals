## Verdict
The JWT signature verification return value is not checked. The code calls `signedJWT.verify()` on line 21 but ignores its boolean result, allowing requests with invalid signatures to proceed and extract claims from unverified tokens.

## Source
Line 21: `signedJWT.verify(new RSASSAVerifier(verificationKey));`

The `verify()` method returns `true` if the signature is valid and `false` if it is invalid, but this return value is never examined. The code continues immediately to extract the subject claim and write the response, treating all JWTs identically regardless of cryptographic validity.

## Fix
Check the boolean return value of `verify()` before proceeding with the request:

```java
public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String authHeader = request.getHeader("Authorization");
    String token = authHeader.substring("Bearer ".length());

    SignedJWT signedJWT = SignedJWT.parse(token);

    if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("Invalid JWT signature");
        return;
    }

    String username = signedJWT.getJWTClaimsSet().getSubject();
    response.getWriter().write("Welcome, " + username);
}
```

## Explanation
CWE-347 occurs when cryptographic signatures are not properly verified before trusting signed data. The Nimbus JOSE library's `SignedJWT.verify()` method returns a boolean indicating whether the signature is cryptographically valid. Ignoring this return value is a complete verification bypass: an attacker can forge or tamper with the JWT (changing claims like the subject/username) and the application will accept it without cryptographic validation.

The fix wraps the verification call in a conditional check. If `verify()` returns `false`, indicating an invalid signature, the request is rejected with HTTP 401 Unauthorized before any claims are extracted or trusted. Only requests bearing JWTs with valid signatures are allowed to proceed.
