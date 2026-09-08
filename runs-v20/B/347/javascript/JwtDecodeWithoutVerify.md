## Verdict

Confirmed. Exploitable as reported.

## Source

`req.headers['authorization']` (line 8) - the bearer token is taken directly from the incoming HTTP request with no server-side control over its contents.

## Fix

### File: JwtDecodeWithoutVerify.js

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

// Middleware that authorizes a request using the bearer token's claims.
app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  let claims;
  try {
    claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(401).send('Invalid token');
  }

  if (!claims || claims.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }

  req.user = claims;
  next();
});

app.get('/admin/dashboard', (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}` });
});

module.exports = app;
```

## Explanation

The middleware extracted a bearer token from the `Authorization` header and passed it straight to `jwt.decode()`, which parses and base64-decodes the JWT payload without checking the signature at all - it will happily return a claims object for a token nobody ever signed. The subsequent authorization check (`claims.role !== 'admin'`) trusted that unverified payload, so an attacker could construct a JWT with an arbitrary header/payload (no valid signature needed), set `role: "admin"` in the payload, and reach `/admin/dashboard`.

The fix replaces `jwt.decode(token)` with `jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })` from the same `jsonwebtoken` package already in use. `verify()` cryptographically checks the signature against `JWT_SECRET` and throws (`JsonWebTokenError`, `TokenExpiredError`, etc.) if the signature is missing, invalid, or the header's algorithm isn't in the explicit `algorithms` allowlist - this also blocks the classic `alg: none` and algorithm-confusion bypasses, since the algorithm actually used is pinned rather than trusted from the token header. The secret is read once from `process.env.JWT_SECRET` at module load and the module refuses to start if it's unset, rather than falling back to a hardcoded or default secret that would make every token forgeable.

Confirmed no fixed release is needed for this: the vulnerability here is call-site misuse (`decode()` instead of `verify()`), not a version-specific library defect, so no `package.json` change is required. `jsonwebtoken`'s installed version should still be confirmed at 9.0.0+ via SCA tooling as defense in depth per the loaded guidance, since versions before 9.0.0 have no automatic algorithm inference at all - but that is orthogonal to this finding, which is present regardless of version.

**Assumption:** the signing algorithm actually used to mint tokens for this application is not shown in the provided file. `HS256` is assumed as the explicit `algorithms` entry because the fix uses a single shared-secret string (consistent with an HMAC secret, not an RSA/EC public key). If tokens are actually signed with an asymmetric algorithm (e.g. RS256), `JWT_SECRET` must instead be the corresponding public key/certificate and `algorithms` updated to match - the actual signing algorithm and key material should be confirmed against how tokens are issued elsewhere in the application before merging.

**Check performed:** `node --check` was run against the fixed file in a scratch location (not the case directory) and reported no syntax errors. Every API used by the fix - `jwt.verify()`, its `algorithms` option, and `process.env` - is either already imported in the original file (`jsonwebtoken`) or Node.js standard library; none are new dependencies.

## Behaviour changes

- **Requests with a forged/unsigned token are now rejected (this is the fix's purpose):** a token whose payload claims `role: "admin"` but lacks a valid signature previously passed straight through to the `role` check and could reach `/admin/dashboard`; it now fails signature verification and gets `401 Invalid token`.
- **Malformed or unparseable tokens now return `401` instead of `403`:** previously `jwt.decode()` returned `null` for a malformed token, which fell through to `403 Forbidden`. `jwt.verify()` throws for the same input, which the new `catch` block turns into `401 Invalid token`. Callers distinguishing these two status codes will see the code change.
- **Expired tokens are now rejected where they previously were not:** `jwt.decode()` never checked the `exp` claim; `jwt.verify()` does by default and throws `TokenExpiredError`, now surfaced as `401 Invalid token`.
- **New required configuration:** the module now requires a `JWT_SECRET` environment variable and will throw at load time if it is missing, rather than the previous code path, which needed no secret at all. This is an intentional fail-closed change, not an incidental one, but it does mean the process will not start without that variable set.
- **Algorithm is now pinned to `HS256`** (see Assumption above): a legitimately-issued token signed with any other algorithm will now be rejected where it previously would have been decoded and trusted.
