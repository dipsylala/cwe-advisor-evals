## Verdict

Exploitable. Confidence: high.

CWE-347 (Improper Verification of Cryptographic Signature) at `JwtDecodeWithoutVerify.js:16`. `jwt.decode()` parses and base64url-decodes the JWT payload but performs no cryptographic verification of the signature at all - not a version-gated weakness, but the documented behavior of `decode()` on every `jsonwebtoken` release. Any caller can submit a token with an arbitrary payload (`{"role":"admin",...}`), an unverified or absent signature, and even `"alg":"none"`, and `decode()` returns that payload as-is.

## Source

`req.headers['authorization']` (the client-supplied bearer token), stripped of the `Bearer ` prefix into `token` at line 9. This is attacker-controlled input with no upstream validation or trust boundary before it reaches the sink.

Sink: `jwt.decode(token)` at line 16. The returned `claims` object is used directly for an authorization decision (`claims.role !== 'admin'`) and then attached to `req.user` for downstream handlers, so an unverified, attacker-forged payload directly grants admin access to `/admin/dashboard`.

## Fix

Vulnerable code:

```js
  // SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
  const claims = jwt.decode(token);

  if (!claims || claims.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
```

Fixed code:

```js
  // Verify the signature before trusting any claim in the token.
  // JWT_SECRET must be the same key used to sign tokens on issuance.
  let claims;
  try {
    claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(401).send('Invalid token');
  }

  if (!claims || claims.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
```

Library recommendation: confirm the installed `jsonwebtoken` version is at least 9.0.0 (GHSA-hjrf-2m68-5959) via SCA/dependency-check tooling before merging. This file has no manifest to inspect, so the version cannot be confirmed here. Below 9.0.0, `jwt.verify()` without an explicit `algorithms` option performs no algorithm restriction at all (the unmitigated classic bypass); 9.0.0+ infers `algorithms` from the key's type, which is a secondary hardening, not a substitute for the explicit array shown above.

## Explanation

The fix replaces `jwt.decode()`, which never checks the signature, with `jwt.verify()`, which cryptographically validates the signature against a server-held key before returning any claims, and throws (`JsonWebTokenError`/`TokenExpiredError`) on a forged, tampered, expired, or malformed token. The `algorithms: ['HS256']` option is passed explicitly and hardcoded rather than relying on library inference, closing algorithm-confusion attacks (e.g. an attacker re-signing a token as `HS256` using a known public key, or submitting `alg: none`) regardless of the installed `jsonwebtoken` version. The existing `!claims || claims.role !== 'admin'` authorization check and the `req.user = claims` assignment are left in place and now operate only on claims that have passed signature verification, so a caller can no longer reach the admin branch by presenting an unsigned or arbitrarily-signed token.

## Behaviour changes

- Added a `try`/`catch` around the sink, returning `401 Invalid token` on a verification failure. `jwt.decode()` never throws (it returns `null` on a malformed token, handled by the pre-existing `!claims` check); `jwt.verify()` throws on any signature, expiration, or algorithm mismatch, so the catch is required to preserve the middleware's fail-closed contract instead of an unhandled exception reaching Express's default error handler. This is the direct consequence of closing the weakness, not an unrelated change.
- Introduced `process.env.JWT_SECRET` as the verification key. The original code held no key material anywhere - `decode()` takes none - so this is a new, load-bearing input the fix requires. Assumption: the token is HMAC-signed (`HS256`) and the verification secret is available via an environment variable named `JWT_SECRET`; the file that issues these tokens is outside this case's single file, so neither the signing algorithm nor the key source could be confirmed from the code shown. If the actual deployment signs with RS256/ES256 via an asymmetric key or a `kid`-based JWKS lookup, the key argument and `algorithms` array must be updated to match that scheme - do not reuse an HMAC secret as source material for an RSA/EC public key path.
- Did not add `issuer`/`audience`/`clockTolerance` options (recommended defense-in-depth in the loaded guidance). The original code carries no evidence of an expected issuer or audience value, so adding one would invent configuration that doesn't exist in this file rather than fix the reported weakness; a developer with access to the token-issuance code should add these once the expected values are known.
