## Verdict

CWE-347 (Improper Verification of Cryptographic Signature) - **exploitable**. Confidence: high.

`jwt.decode()` parses and base64-decodes a JWT's payload without checking the signature at all. The middleware then trusts `claims.role` straight out of that unverified payload to grant `/admin` access. An attacker can hand-craft a token with header `{"alg":"none"}` or any arbitrary signature, base64url-encode a payload containing `{"role":"admin"}`, and send it as the bearer token - `jwt.decode()` returns the forged claims exactly as if they were authentic, and the `role !== 'admin'` check passes.

## Source

- **Source**: `req.headers['authorization']`, line 8 - attacker-controlled HTTP header, stripped of the `Bearer ` prefix into `token` (line 9).
- **Sink**: `jwt.decode(token)`, line 16 - the decoded payload is assigned to `claims` and immediately used for an authorization decision (`claims.role !== 'admin'`, line 18) and later trusted as `req.user` (line 22), with no call to `jwt.verify()` anywhere in the file and no signature check of any kind between source and sink.

## Fix

**Library recommendation**: `jsonwebtoken` is already a dependency (`require('jsonwebtoken')`). No manifest file is present in this case directory to confirm the installed version, so confirm via SCA/dependency-check tooling that it is at least `9.0.0` (GHSA-hjrf-2m68-5959) before relying on the library's own key-type inference; the code below adds an explicit `algorithms` restriction regardless of version, which is required defense-in-depth even on 9.0.0+.

Vulnerable code (line 16):

```js
// SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
const claims = jwt.decode(token);
```

Fixed code:

```js
app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  let claims;
  try {
    // Signature is verified against the server-held secret and restricted to the
    // expected algorithm; the key never comes from the token itself.
    claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(401).send('Invalid token');
  }

  if (!claims || claims.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }

  req.user = claims;
  next();
});
```

## Explanation

`jwt.decode()` is replaced with `jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })`, wrapped in a try/catch because `verify()` throws on any signature, expiry, or format failure rather than returning a best-effort payload. This closes the weakness because `claims` can now only be populated from a token whose signature was cryptographically checked against a server-held secret - a forged or unsigned token throws `JsonWebTokenError` and is rejected with 401 before the role check ever runs. The explicit hardcoded `algorithms: ['HS256']` array is required defense-in-depth per the loaded guidance: it prevents an attacker from switching the token's declared algorithm (e.g. to `none` or to a mismatched family) to bypass verification, independent of whatever key-type inference the installed `jsonwebtoken` version does. The verification secret is read from `process.env.JWT_SECRET`, a value the request never influences, keeping the key itself outside attacker control - the original code had no key material or verification call at all, so a symmetric HMAC secret is assumed here; if the real deployment issues RS256/ES256 tokens, the `algorithms` value and the second argument must instead reference the corresponding public key from configuration or a keystore, not a shared secret.

## Behaviour changes

- **Added verification failure path (401)**: a token with an invalid/mismatched signature, malformed structure, or unsupported algorithm now throws inside `jwt.verify()` and is caught, returning `401 Invalid token`. Previously `jwt.decode()` either returned the (unverified) payload or `null` on a malformed token, which fell through to the `403 Forbidden` branch. This is required by the fix - the whole point is to reject unverified tokens before the role check.
- **Expiration is now enforced**: `jwt.verify()` checks the token's `exp` claim (when present) and throws `TokenExpiredError` for expired tokens, caught and mapped to 401. `jwt.decode()` never checked expiration. This is a direct, intended consequence of switching to a verifying call, not an unrelated change.
- **New runtime dependency on `process.env.JWT_SECRET`**: the fixed code requires this environment variable to be configured with the same secret used to sign legitimate tokens. The original code had no verification key of any kind. This is unavoidable - `jwt.verify()` cannot check a signature without a key - and the exact secret/algorithm pair (HS256 vs. an asymmetric alg) must be confirmed against how the application's tokens are actually signed before deployment; this is called out as an assumption above rather than silently guessed.
- Response shapes, the 401/403 status codes used for the pre-existing "missing token" and "wrong role" branches, and the successful-auth path (`req.user = claims; next()`) are unchanged.
