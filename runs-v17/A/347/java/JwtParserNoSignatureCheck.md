## Verdict
The code calls `signedJWT.verify()` but does not check its return value. The `verify()` method returns a boolean indicating whether signature verification succeeded. If verification fails, the method returns false, but the code continues to extract and use the JWT claims regardless. This allows an attacker to pass a JWT with an invalid, expired, or tampered signature, and the application will still trust the claims within it.

## Source
```java
SignedJWT signedJWT = SignedJWT.parse(token);

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
signedJWT.verify(new RSASSAVerifier(verificationKey));

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

The vulnerability is at line 21: the return value of `verify()` is ignored, and execution proceeds unconditionally to use the unverified JWT claims.

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

        // Verify the signature and check the result before using any claims
        if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid token signature");
            return;
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();
        response.getWriter().write("Welcome, " + username);
    }
}
```

## Explanation
The fix checks the boolean return value of `signedJWT.verify()` and only proceeds to use the JWT claims if verification succeeds. If the signature verification fails, the handler responds with HTTP 401 Unauthorized and returns an error message, rejecting the request entirely. This ensures that only JWTs with valid signatures cryptographically verified against the expected public key are accepted, preventing attackers from forging or tampering with tokens.
