## Verdict

CONFIRMED. The code calls `signedJWT.verify(new RSASSAVerifier(verificationKey))` at line 21 but ignores the boolean return value. The `verify()` method returns `true` only if the signature is valid; when it returns `false`, the verification has failed. By not checking this return value, the application proceeds to extract and trust the token's claims (`getSubject()`) regardless of whether the signature was valid. An attacker can forge a JWT token and it will be accepted as long as it parses correctly, because signature validation is performed but the result is discarded.

## Source

The vulnerable code is in `JwtParserNoSignatureCheck.java` at line 21:

```java
signedJWT.verify(new RSASSAVerifier(verificationKey));

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

The call to `verify()` has no effect on program flow — the return value is not captured or checked, so execution proceeds unconditionally to line 23 regardless of whether the signature was valid or forged.

## Fix

### File: JwtParserNoSignatureCheck.java

```java
package evalcases;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.interfaces.RSAPublicKey;

public class JwtParserNoSignatureCheck {

    private RSAPublicKey verificationKey;

    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String authHeader = request.getHeader("Authorization");
        String token = authHeader.substring("Bearer ".length());

        SignedJWT signedJWT = SignedJWT.parse(token);

        // SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
        if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
            throw new SecurityException("JWT signature verification failed");
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();
        response.getWriter().write("Welcome, " + username);
    }
}
```

## Explanation

The fix adds a conditional check on the return value of `signedJWT.verify()`. The `verify()` method returns `true` if the signature is valid and `false` if it is invalid or cannot be verified. By wrapping the verification call in an `if (!...)` condition, the code now rejects the token immediately if the signature is invalid, throwing a `SecurityException` to signal the authentication failure. The subsequent calls to `getJWTClaimsSet()` and `getSubject()` only execute if the signature is valid.

This satisfies the CWE-347 remediation principle: "Fail securely on verification errors — Reject data immediately on any verification failure." The token claims are now trusted only after a successful signature verification.

## Behaviour changes

- **Before**: A forged or unsigned JWT token is accepted if it parses correctly, because the signature verification is performed but its result is ignored. The application extracts and uses the `subject` claim from any syntactically valid token.
- **After**: Only a JWT token with a valid signature matching the configured RSA public key is accepted. If the signature verification fails, a `SecurityException` is thrown before any claims are extracted or used, causing the request to fail and preventing the attacker-controlled username from being used.
