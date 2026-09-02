## Verdict

CWE-347 (Improper Verification of Cryptographic Signature) - **exploitable**, confidence: high.

`SignedJWT.verify(JWSVerifier)` returns a `boolean` rather than throwing on an invalid signature. The reported line calls it and discards the result, so a token with a forged or mismatched signature parses successfully, its claims are read, and the request is treated as authenticated regardless of whether the signature actually checked out.

## Source

- **Source**: `request.getHeader("Authorization")` (line 15) - attacker-controlled bearer token, stripped of the `Bearer ` prefix and handed to `SignedJWT.parse(token)` (line 18) with no further validation.
- **Sink**: `signedJWT.verify(new RSASSAVerifier(verificationKey))` (line 21). `RSASSAVerifier` itself is constructed correctly - it is bound to a fixed, server-held `RSAPublicKey` (never derived from the token) and only accepts the RSA signature family, so this is not an algorithm-confusion case. The defect is that the call's return value is never inspected: the method returns `true`/`false`, and the code proceeds identically either way to `signedJWT.getJWTClaimsSet().getSubject()` (line 23) and writes `username` into the response as an authenticated identity (line 24).

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
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token signature");
    return;
}

String username = signedJWT.getJWTClaimsSet().getSubject();
response.getWriter().write("Welcome, " + username);
```

## Explanation

The fix captures the `boolean` that `SignedJWT.verify()` already returns and branches on it instead of discarding it. On `false` the request is rejected with `401 Unauthorized` and the method returns before any claim is read or trusted; only a token whose RSA signature checks out against the server-held `verificationKey` reaches the claims extraction and response-writing code. No verification logic changes - `RSASSAVerifier` was already correctly scoped to the RSA family and bound to a trusted, non-token-derived key - the fix is solely enforcing the result that call already produces, closing the gap where an unchecked `verify()` was indistinguishable from a successful one.

## Behaviour changes

- Requests bearing a token with an invalid or mismatched signature now receive `401 Unauthorized` and no body, whereas previously they received `200 OK` with `"Welcome, <subject-claim>"` using unverified claim data. This is the intended effect of closing the weakness, not incidental scope creep.
- No other arguments, return values, or control flow were altered: `RSASSAVerifier` is constructed with the same key and the same way; the success path (valid signature) is byte-for-byte the same response as before.
