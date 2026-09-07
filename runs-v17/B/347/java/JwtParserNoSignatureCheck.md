## Verdict

**CONFIRMED VULNERABILITY** – CWE-347 (Improper Verification of Cryptographic Signature)

The code verifies the JWT signature but fails to:
1. Check the return value of `verify()` (currently discarded)
2. Validate the algorithm in the JWT header against an expected allowlist

This enables algorithm-confusion attacks where an attacker sends a JWT claiming `alg: HS256` or `alg: none`, potentially bypassing signature verification.

## Source

File: `JwtParserNoSignatureCheck.java`, line 21

```
String token = authHeader.substring("Bearer ".length());
SignedJWT signedJWT = SignedJWT.parse(token);
signedJWT.verify(new RSASSAVerifier(verificationKey));  // ← CWE-347: return value ignored, algorithm unchecked
String username = signedJWT.getJWTClaimsSet().getSubject();
```

The token originates from untrusted HTTP input and the JWT header's algorithm field is never validated against an expected value.

## Fix

### File: JwtParserNoSignatureCheck.java

```java
package evalcases;

import com.nimbusds.jose.JOSEException;
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

        // Verify the signature and reject if invalid
        if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
            throw new JOSEException("Signature verification failed");
        }

        // Pin the algorithm to prevent algorithm-confusion attacks
        String algorithm = signedJWT.getHeader().getAlgorithm();
        if (!"RS256".equals(algorithm)) {
            throw new JOSEException("Unexpected algorithm: " + algorithm);
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();
        response.getWriter().write("Welcome, " + username);
    }
}
```

## Explanation

The fix enforces two critical checks:

1. **Check verify() return value**: `SignedJWT.verify()` returns a boolean. The original code ignored this result, meaning even a failed verification would continue to the claims extraction. The fixed code throws `JOSEException` if verification fails, stopping execution immediately.

2. **Pin the algorithm**: The JWT header's `alg` field is attacker-controlled and must be validated against an expected allowlist before the claims are used. This prevents algorithm-confusion attacks where an attacker sends a token with `alg: HS256` or `alg: none`. The fix extracts `getHeader().getAlgorithm()` and compares it to the hardcoded expected value `"RS256"`. Any other algorithm is rejected.

Per the Java CWE-347 guidance: "Pin the exact verification algorithm and key type; never let the token header...select the algorithm family based on attacker input" and "Pin the algorithm rather than reading it from the header."

## Behaviour changes

- **Before**: A JWT with an invalid signature would pass through silently; a JWT with `alg: none` or `alg: HS256` would be accepted as long as the RSA verifier could parse it.
- **After**: Any signature verification failure throws an exception and halts request processing. Any algorithm other than RS256 is rejected immediately.
- **Impact**: Legitimate requests with valid RS256 tokens and valid signatures pass unchanged. Malicious or forged tokens are reliably rejected.
