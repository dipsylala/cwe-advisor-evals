## Verdict

- **cwe_id**: CWE-347 (Improper Verification of Cryptographic Signature)
- **location**: `JwtParserNoSignatureCheck.java`, line 21 (`signedJWT.verify(new RSASSAVerifier(verificationKey))`)
- **verdict**: exploitable
- **confidence**: high

## Source

- **Source**: `request.getHeader("Authorization")` — attacker-controlled bearer token, stripped of the `Bearer ` prefix and parsed directly with `SignedJWT.parse(token)`.
- **Sink**: `signedJWT.verify(new RSASSAVerifier(verificationKey))` at line 21.
- **Data flow**: the raw header value flows unmodified into `SignedJWT.parse()`, then the parsed object is handed to `verify()`. Nothing between the header read and the sink constrains or re-checks the token.
- **Sink contract**: `SignedJWT.verify(JWSVerifier)` (Nimbus JOSE+JWT) *returns* a `boolean` — `true` only if the signature is cryptographically valid for the supplied key — and does not throw on an invalid-but-well-formed signature; it only throws `JOSEException` for verifier/key setup problems. The current code calls `verify()` for its side effect and *discards* the boolean. No arguments are left implicit (the verifier is explicitly typed to the server's own `RSAPublicKey`, so there is no algorithm/key-type confusion here). Because the return value is never inspected, a syntactically valid but unsigned or wrongly-signed JWT proceeds identically to a correctly signed one: execution falls through to `getJWTClaimsSet()` and the claims are trusted regardless of verification outcome.

## Fix

Vulnerable code:

```java
SignedJWT signedJWT = SignedJWT.parse(token);

// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
signedJWT.verify(new RSASSAVerifier(verificationKey));

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

Fixed code:

```java
SignedJWT signedJWT = SignedJWT.parse(token);

boolean signatureValid = signedJWT.verify(new RSASSAVerifier(verificationKey));
if (!signatureValid) {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    return;
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

No library version change is proposed: Nimbus JOSE+JWT's `verify()` API already returns the correct signal (`RSASSAVerifier` is already typed to the server's own `RSAPublicKey`, so there is no header-driven key/algorithm confusion to close). The defect is a usage bug — the return value is discarded — not an outdated or vulnerable dependency, so no CVE/minimum-version claim applies here.

## Explanation

The vulnerability is not a missing verification call — `verify()` is invoked — but an unchecked one: Nimbus's `SignedJWT.verify()` reports success or failure through its `boolean` return rather than by throwing, so ignoring that value makes an invalid signature indistinguishable from a valid one and the request proceeds either way. The fix captures the return value and rejects the request (HTTP 401, no body written) whenever it is `false`, before any claim is read or trusted. This closes the weakness because claims are now reachable only on the path where the signature has been cryptographically confirmed against the server's own RSA public key.

## Behaviour changes

- **Added rejection path**: requests carrying a syntactically well-formed but invalidly- or unsigned JWT now receive `401 Unauthorized` with an empty body instead of a `200` response containing `Welcome, {subject-claim}`. This is the intended effect of closing the CWE-347 finding — previously such requests were served as if authenticated.
- **No change** to the success path: a token with a valid signature produces the same `Welcome, {username}` response as before.
- **No change** to error handling for malformed input: `SignedJWT.parse()` still throws on a malformed token, and `RSASSAVerifier` construction/`verify()` still throws `JOSEException` (propagated via the method's existing `throws Exception`) for verifier/key setup failures — the fix only adds handling for the boolean "signature checked and found invalid" outcome, which the original code silently ignored.
