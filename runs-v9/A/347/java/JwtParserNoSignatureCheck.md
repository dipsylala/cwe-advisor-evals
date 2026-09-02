## Verdict

Confirmed. The signature check is performed but its result is discarded, so an invalid or forged signature does not stop the request from being processed.

## Source

`request.getHeader("Authorization")` on line 15 — the raw bearer token is attacker-controlled input, parsed directly into a `SignedJWT` on line 18 and used to authorize `handleRequest` on lines 21-24.

## Fix

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

`SignedJWT.verify(JWSVerifier)` does not throw on a bad signature and does not mutate the token into a "verified" state as a side effect — it returns a `boolean` indicating whether the signature matched, and leaves the caller responsible for acting on that result. The original code calls `verify(...)` for its side effect only, discards the returned boolean, and then immediately trusts `signedJWT.getJWTClaimsSet()` regardless of whether the check passed. Because `SignedJWT.parse()` only decodes the JWT structure and never validates the signature itself, an attacker can submit a token with an arbitrary payload and any signature bytes (or `alg: none`/a stripped signature, depending on how the header is crafted) and the claims are still read and used to authorize the response.

The fix captures the boolean result of `verify()` and short-circuits with a `401 Unauthorized` response when it is `false`, so `getJWTClaimsSet()` is only reached after the signature has been cryptographically confirmed against `verificationKey`. This preserves the existing control flow and dependency (Nimbus JOSE + JWT's `RSASSAVerifier`) while closing the gap between "signature checked" and "signature enforced." No library upgrade is required; the defect is purely in how the existing API's return value was used.
