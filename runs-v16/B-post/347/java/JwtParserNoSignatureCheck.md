## Verdict
Confirmed. The code uses `SignedJWT.verify()` without pinning the expected signature algorithm, allowing an attacker to perform algorithm confusion (e.g., RS256 to HS256 substitution).

## Source
Line 21: `signedJWT.verify(new RSASSAVerifier(verificationKey));`

The vulnerability is that `SignedJWT.verify()` reads the algorithm (`alg` claim) from the token header rather than enforcing a specific algorithm. An attacker can craft a token with a different algorithm (e.g., HS256 instead of RS256) and sign it with the server's public key treated as an HMAC secret, causing verification to succeed.

## Fix

**Vulnerable code:**
```
SignedJWT signedJWT = SignedJWT.parse(token);
signedJWT.verify(new RSASSAVerifier(verificationKey));
String username = signedJWT.getJWTClaimsSet().getSubject();
```

**Fixed code:**
```
DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
jwtProcessor.setJWSKeySelector(new SingleKeyJWSKeySelector<>(JWSAlgorithm.RS256, verificationKey));

JWTClaimsSet claimsSet = jwtProcessor.processClaims(token, null);
String username = claimsSet.getSubject();
```

**Import changes:**
- Remove: `import com.nimbusds.jose.crypto.RSASSAVerifier;` and `import com.nimbusds.jwt.SignedJWT;`
- Add:
  - `import com.nimbusds.jwt.proc.DefaultJWTProcessor;`
  - `import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;`
  - `import com.nimbusds.jose.JWSAlgorithm;`
  - `import com.nimbusds.jose.proc.SecurityContext;`

## Explanation
The fix replaces unsafe `SignedJWT.verify()` with a `DefaultJWTProcessor` configured with a `SingleKeyJWSKeySelector` that pins both the verification key and the expected algorithm (RS256). This prevents algorithm confusion attacks where an attacker switches to a weaker or symmetric algorithm. The `processClaims()` method verifies the signature using only the configured algorithm and key, then returns the authenticated claims set. By binding the algorithm to the key at configuration time—rather than reading it from the token header—the application rejects any token claiming a different algorithm.

## Behaviour changes
- The processor now explicitly rejects tokens with algorithms other than RS256, preventing algorithm confusion attacks.
- Exceptions are thrown as checked exceptions (`ParseException`, `BadJWTException`, `JOSEException`) which must be handled by the caller (already declared in the method signature via `throws Exception`).
- The claims are extracted directly from `JWTClaimsSet` rather than from a `SignedJWT` object, but the interface remains identical for downstream code.
- No functional change for legitimately signed tokens using RS256; rejected tokens now fail with cryptographic verification failure rather than being silently accepted under a substituted algorithm.
