## Verdict

The code calls `SignedJWT.verify()` but does not check its return value. The `verify()` method returns a boolean indicating whether the signature is valid; an unchecked call is indistinguishable from successful verification. The application proceeds to extract and use claims from the JWT regardless of whether the signature was actually valid, permitting an attacker to forge or tamper with tokens.

## Source

Line 21: `signedJWT.verify(new RSASSAVerifier(verificationKey));`

The return value of `verify()` is discarded. The code then trusts the claims in the JWT without having confirmed the signature is valid.

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

        if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
            throw new IllegalArgumentException("JWT signature verification failed");
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();
        response.getWriter().write("Welcome, " + username);
    }
}
```

## Explanation

The fix adds a conditional check on the return value of `verify()`. If the method returns `false`, indicating that the signature verification failed, an exception is thrown immediately and claim extraction is skipped. Only if the signature is valid (`verify()` returns `true`) does the code proceed to read and use the JWT's claims. This prevents an attacker from bypassing signature validation by supplying a forged or unsigned token.

## Behaviour changes

- **Success case**: Valid, properly signed tokens are accepted and processed as before.
- **Failure case**: Tokens with invalid or missing signatures now reject with an `IllegalArgumentException` before any claims are extracted or used. Previously, such tokens were silently accepted.
- **No change to algorithm pinning**: This fix addresses the missing verification check; the underlying code already passes a specific `RSASSAVerifier` instance, which pins RSA verification. This is acceptable for the immediate finding but should be reviewed for algorithm-confusion risks in production (e.g., ensuring `alg=none` rejection, per CWE-347 Java guidance).
