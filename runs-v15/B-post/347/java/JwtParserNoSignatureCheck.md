## Verdict

exploitable

## Source

Bearer token from HTTP `Authorization` header (line 16: `String token = authHeader.substring("Bearer ".length());`)

## Fix

Vulnerable code (line 21):
```java
signedJWT.verify(new RSASSAVerifier(verificationKey));
```

Fixed code:
```java
if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
    throw new SecurityException("JWT signature verification failed");
}
```

## Explanation

The vulnerability is that `SignedJWT.verify()` returns a boolean indicating whether the signature is valid, but the current code ignores this return value. This allows an attacker to forge or modify a JWT token, and the code will accept it as valid and use its claims. The fix checks the return value and throws an exception if verification fails, preventing the code from using an unverified token. This enforces the principle that data must not be trusted until its signature has been cryptographically verified.

## Behaviour changes

The code now throws `SecurityException` when JWT signature verification fails (previously would silently continue). This is a necessary change to close the vulnerability: a verification function that returns a boolean must have its return value checked, otherwise the verification is ineffective. The exception should be caught at a higher level (e.g., in the servlet filter or error handler) to return an appropriate HTTP error response.
