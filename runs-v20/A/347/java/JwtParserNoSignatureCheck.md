## Verdict

Confirmed. `SignedJWT.verify(JWSVerifier)` (Nimbus JOSE+JWT) returns a `boolean` indicating whether the signature check passed - it does not throw on a bad or forged signature and it does not reject the token itself. The code at line 21 calls `verify()` but discards that return value, then unconditionally proceeds to read claims and use them at line 23-24. An attacker who sends a JWT with an invalid signature, a stripped signature, or a signature produced with a different key gets `verify()` returning `false`, and the request is processed anyway as if the token were trustworthy.

## Source

`request.getHeader("Authorization")` at line 15 - attacker-controlled HTTP header, split into the bearer token at line 16 and parsed into a `SignedJWT` at line 18.

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

        boolean signatureValid = signedJWT.verify(new RSASSAVerifier(verificationKey));
        if (!signatureValid) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token signature");
            return;
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();
        response.getWriter().write("Welcome, " + username);
    }
}
```

## Explanation

Nimbus JOSE+JWT deliberately separates parsing (`SignedJWT.parse`, which only decodes the token's structure and never checks the signature) from verification (`verify(JWSVerifier)`, which checks it and reports the result as its return value). Neither step throws when a signature is missing, malformed, or simply wrong - the caller is required to inspect the boolean. Because the original code ignored that return value, the call to `verify()` had no effect on control flow: every syntactically well-formed JWT reached `getJWTClaimsSet()` regardless of who signed it or whether it was signed at all, letting an attacker forge a token with an arbitrary `sub` claim and impersonate any user.

The fix captures the result of `verify()` and short-circuits the request with `401 Unauthorized` when it is `false`, so claims are read only after the signature has been cryptographically confirmed to be a valid RSA signature over that exact payload made by the holder of the private key corresponding to `verificationKey`. This is the minimal, correct fix for the reported finding: it makes the existing verifier call actually gate access instead of running as a no-op. It does not change the verification algorithm, key material, or parsing logic, so it does not introduce an algorithm-confusion or key-management issue of its own.
