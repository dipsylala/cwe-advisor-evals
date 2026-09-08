## Verdict

Exploitable. `jwt.decode()` performs a plain base64 decode of the JWT payload with no signature check at any version of `jsonwebtoken`. An attacker can craft an arbitrary payload - including `role: "admin"` and any `userId` - base64-encode it into a JWT-shaped string, and submit it as the bearer token; `requireAdmin` will accept it as an authenticated admin because nothing in the function ever verifies the token was issued by the server.

## Source

`req.headers['authorization']`, the client-supplied `Authorization` header, split on `' '` to extract `token` (line 9).

## Fix

### File: authMiddleware.js
```javascript
// authMiddleware.js
// Express middleware that protects the internal admin API.
// Uses jsonwebtoken@9.0.2.
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    res.set('WWW-Authenticate', 'Bearer');
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    res.set('WWW-Authenticate', 'Bearer');
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (!payload || !payload.userId) {
    res.set('WWW-Authenticate', 'Bearer');
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (payload.role !== 'admin') {
    return res.status(403).json({ error: 'Admin role required' });
  }

  req.user = { id: payload.userId, role: payload.role };
  next();
}

module.exports = { requireAdmin };
```

## Explanation

The sink at line 16 has been changed from `jwt.decode(token)` to `jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })` wrapped in a `try`/`catch`. `jwt.decode()` never checks a signature at any version of `jsonwebtoken`, so any base64-encoded JSON payload was accepted as a trusted identity claim regardless of who produced it. `jwt.verify()` cryptographically checks the signature against `JWT_SECRET` (the key that must have been used to issue legitimate tokens) and, because `exp`/`nbf` are enforced by default (`ignoreExpiration` is left unset, i.e. `false`), also rejects expired or not-yet-valid tokens. Pinning `algorithms: ['HS256']` closes algorithm-confusion: without it, `jsonwebtoken` would infer acceptable algorithms from the key format, letting a token forged with a different algorithm family potentially validate against the same secret. `jwt.verify()` throws synchronously (`JsonWebTokenError`, `TokenExpiredError`, `NotBeforeError`, etc.) on any signature, expiry, or format failure instead of returning `null` the way `jwt.decode()` did, so the `try`/`catch` maps every such failure to the same `401 Invalid token` response the code already used for a missing/falsy payload. The library itself needs no version change: the file's own header comment already pins `jsonwebtoken@9.0.2`, which is above the 9.0.0 floor that closed CVE-2022-23539/23540/23541.

## Behaviour changes

- **New required configuration: `JWT_SECRET`.** The fix introduces `const JWT_SECRET = process.env.JWT_SECRET`, a value the original code never needed (`jwt.decode()` takes no key). This is an assumption, not something derivable from this file alone: the actual signing secret/key material and algorithm the token issuer uses are not visible in this file. If the issuer signs with RS256/ES256 (asymmetric) rather than HS256, `JWT_SECRET` must instead be the issuer's public key/certificate and `algorithms` must list the actual algorithm (e.g. `['RS256']`) - using the wrong algorithm list or key type will make `jwt.verify()` reject every legitimate token (fail closed, not an auth bypass, but an availability regression if misconfigured). This value must be sourced from the same secret store the token issuer uses, outside source control.
- **`WWW-Authenticate: Bearer` header added to all three `401` responses.** The original code returned `401` with a JSON body only. The root CWE-287 guidance requires a `401` to carry the `WWW-Authenticate` challenge header; this was added to the existing missing-token branch and the two new/retained invalid-token branches. It does not change the JSON body or status code any client already handles.
- **Failure mode changed from "malformed payload passes through as `null`" to "thrown exception caught and mapped to 401".** `jwt.decode()` returns `null` on a malformed token and the existing `!payload` check turned that into `401`. `jwt.verify()` throws on the same malformed input (and additionally on a bad signature, wrong algorithm, or expired/not-yet-valid token, none of which `jwt.decode()` ever rejected). The `try`/`catch` normalizes all of these to the identical `401 { error: 'Invalid token' }` response, so no new response shape was introduced.
- Everything downstream of `payload` (`payload.userId`, `payload.role`, the `req.user` assignment, the `403` branch, `next()`) is unchanged - it still only sees the object returned by the token check, matching the guidance's "attach only the verified claims to `req.user`" step.

## Verification

`node --check` was run against the fixed file (copied to a scratch location, not the case directory) and returned no output, confirming valid syntax. `jwt.verify`, `res.set`, and `try`/`catch` are all either the same `jsonwebtoken` API already imported in the original file or JavaScript/Express built-ins, so no new dependency was introduced. No test runner was available in this context to execute the guidance's suggested right/wrong-token timing and `alg: none`/re-signed-token rejection tests; those are recommended follow-up verification once this fix is applied in the real codebase.
