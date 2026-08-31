## Verdict

Exploitable. The `SignedJWT.verify()` method returns a boolean but its result is discarded, allowing unverified or forged JWTs to be accepted. Attackers can supply unsigned tokens, and the code will extract and trust their claims.

## Source

JWT token from HTTP Authorization header (`request.getHeader("Authorization")`, line 15), parsed into a SignedJWT object on line 18.

## Fix

**Vulnerable code:**

```java
signedJWT.verify(new RSASSAVerifier(verificationKey));

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

**Fixed code:**

```java
if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
    throw new SecurityException("JWT signature verification failed");
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

## Explanation

The original code calls `signedJWT.verify()` but ignores its boolean return value, permitting unverified tokens to proceed to claims extraction. The fix checks the return value: if verification fails (returns false), a SecurityException is thrown immediately, preventing untrusted claims from being used. This enforces the principle that signatures must be validated before any data from the token is trusted.

## Behaviour changes

- The fixed code now throws `SecurityException` when JWT signature verification fails, whereas the original code silently accepted verification failure and continued execution. This is the intended and necessary change to eliminate the weakness—unverified JWTs must never reach claims extraction. The exception will propagate to the servlet container or application error handler, which should log the event and return an HTTP 401/403 response to the client.
