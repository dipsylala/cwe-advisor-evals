## Verdict

The code calls `signedJWT.verify()` but does not check its return value. The Nimbus JOSE library's `verify()` method returns a boolean; ignoring this result means an invalid signature fails silently and the token is processed anyway, bypassing authentication.

## Source

Line 21 calls `verify()` without checking the result:

```
signedJWT.verify(new RSASSAVerifier(verificationKey));
```

The code then immediately accesses the JWT claims and responds to the user regardless of whether verification succeeded.

## Fix

Check the boolean return value of `verify()` and only proceed if it returns `true`. Reject the request with an HTTP 401 Unauthorized response if verification fails:

```java
if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.getWriter().write("Invalid token signature");
    return;
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

## Explanation

CWE-347 arises when a cryptographic signature verification operation completes without raising an exception but the result is not checked. Nimbus JOSE's `verify()` returns `false` for an invalid signature rather than throwing an exception by default. Discarding this return value leaves the application processing unauthenticated or tampered tokens. The fix enforces that the signature must be valid before any claims are extracted or acted upon, and rejects the request if verification fails.
