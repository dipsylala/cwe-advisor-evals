## Verdict

Exploitable. CWE-347 (Improper Verification of Cryptographic Signature).

- Location: `JwtParserNoSignatureCheck.java`, line 21 (`signedJWT.verify(new RSASSAVerifier(verificationKey))`).
- Confidence: high.

## Source

- Source: the `Authorization` header (`request.getHeader("Authorization")`, line 15) - fully attacker-controlled. The `Bearer ` prefix is stripped and the remainder is parsed straight into a `SignedJWT` (line 18).
- Sink: `signedJWT.verify(new RSASSAVerifier(verificationKey))` (line 21).
- Data flow: the raw header value flows unmodified from `request.getHeader()` into `SignedJWT.parse()` and then into `verify()`; nothing on this path constrains or validates it beforehand, so the trace confirms the path is live, not merely unproven.
- Sink contract: `SignedJWT.verify(JWSVerifier)` (Nimbus JOSE+JWT) returns a `boolean` - `true` only if the signature validates against the supplied key, `false` for any invalid or forged signature. It does not throw on a bad signature (a `JOSEException` is reserved for verifier/processing errors, e.g. a malformed key). The current code calls `verify()` and discards the returned value: `getJWTClaimsSet()` and the response write on lines 23-24 execute unconditionally, regardless of whether the signature actually checked out.
- Consequence: an attacker can send any syntactically valid, arbitrarily-signed (or garbage-signed) JWT with a forged `sub` claim; `verify()` returns `false`, that result is thrown away, and the handler still trusts the claim and greets the forged username. This is exactly the pattern flagged for Java in the loaded guidance: "`Signature.verify()` returns a boolean rather than throwing - an unchecked call is indistinguishable from a successful verification."

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

        if (!signedJWT.verify(new RSASSAVerifier(verificationKey))) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token signature");
            return;
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();
        response.getWriter().write("Welcome, " + username);
    }
}
```

## Explanation

The only change is checking the boolean `verify()` returns and rejecting the request when it is `false`, instead of discarding the result and proceeding unconditionally. `SignedJWT.verify()` already runs the correct check against `RSASSAVerifier(verificationKey)` - the RSA public key never came from attacker input, so nothing about the verifier setup itself needed to change - the defect was purely that a failed verification was never acted on. Wrapping the call in `if (!signedJWT.verify(...))` and returning a `401 Unauthorized` before any claim is read closes the path: a token with an invalid, forged, or missing signature can no longer reach `getJWTClaimsSet()` or the response write, so a forged `sub` claim can no longer be trusted or echoed back.

## Behaviour changes

- A request bearing a JWT whose signature does not verify now receives an HTTP 401 response (`response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ...)`) instead of a 200 response echoing the token's (unverified) `sub` claim. This is the intended effect of closing the weakness, not an incidental change: rejecting an unverified token is the fix.
- A request whose signature does verify is handled identically to before - same claims lookup, same response body and status.
- No new imports, dependencies, or library version changes. `HttpServletResponse.sendError(int, String)` is part of the already-imported `javax.servlet.http.HttpServletResponse` (Servlet API), so no new symbol had to be introduced beyond an existing class's existing method.
- No change to key management, algorithm acceptance, or claim validation (issuer/audience/expiration) - out of scope for this finding, which is specifically the discarded `verify()` result.

Verification performed: no Java compiler/build environment for this module (Nimbus JOSE+JWT, Servlet API) was available in this environment, so the fix was checked by manual review rather than `javac`: the only introduced construct is `if (!signedJWT.verify(...)) { response.sendError(...); return; }`, which uses `signedJWT.verify` and `RSASSAVerifier` exactly as the original code did (same call, same arguments) and `HttpServletResponse.sendError(int, String)`, a standard two-argument overload on the already-imported, already-used `HttpServletResponse` type. All brace/statement structure was checked by hand against the original method body, and control flow was confirmed to `return` before any post-verification statement can execute on the rejection path.
