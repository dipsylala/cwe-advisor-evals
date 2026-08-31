## Verdict

Confirmed. The signature check is performed but its result is discarded, so an unsigned or invalidly-signed JWT is processed identically to a validly-signed one.

## Source

`request.getHeader("Authorization")` at line 15 — the client-supplied bearer token, `token`, flows unmodified into `SignedJWT.parse(token)` at line 18.

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

`SignedJWT.verify(JWSVerifier)` in the Nimbus JOSE+JWT library does not throw on a bad signature and does not reject the token internally — it returns a `boolean` indicating whether the signature matched, and it is the caller's responsibility to act on that result. The original code calls `signedJWT.verify(...)` at line 21 purely for its side effect and never inspects the return value, so execution falls through to `getJWTClaimsSet().getSubject()` and the welcome response regardless of whether the signature was valid. An attacker can therefore submit a JWT with an arbitrary payload and an invalid, missing, or algorithm-swapped signature (e.g. one signed with a different key, or with `alg: none` if the parser accepts it) and still have its claims trusted, allowing full impersonation of any subject.

The fix captures the boolean returned by `verify()` and short-circuits with an HTTP 401 response when it is `false`, ensuring the claims are only read and trusted after the signature has been cryptographically confirmed against `verificationKey`. This also implicitly enforces that the token was signed with RS256/RSA (matching `RSASSAVerifier`), since a token using a different or absent algorithm will fail verification rather than being silently accepted.
