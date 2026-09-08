## Verdict

exploitable (confidence: high)

## Source

`Authorization` request header (`req.headers['authorization']`), split into scheme and bearer `token` in `requireAuth`. The token is attacker-controlled: any caller can set this header to an arbitrary value, including a self-crafted JWT with a header of their choosing.

## Fix

### File: authMiddleware.js

```javascript
// authMiddleware.js
// Express middleware that authenticates API requests using an RS256-signed
// JWT. The RSA public key is loaded once at startup and used to verify the
// bearer token on every request. Targets jsonwebtoken 9.0.2.

const fs = require('fs');
const jwt = require('jsonwebtoken');

const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, 'utf8');

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    req.user = { id: claims.sub, roles: claims.roles || [] };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireAuth };
```

## Explanation

`jwt.verify(token, publicKey)` is called with no `algorithms` option, so `jsonwebtoken` lets the token's own header pick the verification algorithm instead of the server pinning it. Because the "key" material handed to `verify()` is the PEM-encoded RSA *public* key - a value that is not secret and is often distributable to clients or discoverable via a JWKS/well-known endpoint - an attacker can craft a token with header `alg: HS256`, HMAC-sign it using the public key's raw bytes as the shared secret, and have `jwt.verify()` accept it as a validly signed token, forging arbitrary claims (`sub`, `roles`, etc.) that flow straight into `req.user`. This is the classic RS256-to-HS256 algorithm-confusion bypass. The fix adds `{ algorithms: ['RS256'] }` to the `verify()` call, which is the sole algorithm this deployment's issuer signs with per the file's own header comment; `jsonwebtoken` then rejects any token whose header names a different algorithm, throwing `JsonWebTokenError` before any HMAC/RSA verification is attempted against attacker-chosen key material, closing the confusion path while leaving legitimate RS256 tokens unaffected.

## Behaviour changes

- Added `{ algorithms: ['RS256'] }` as the third argument to `jwt.verify()`. This is the only change. For any token actually signed by the real issuer with RS256 (the documented signing algorithm), verification behavior, the returned `claims` object, and the `req.user` assignment are all unchanged. The only behavior difference is that a token whose header specifies any algorithm other than `RS256` (e.g. `HS256`, `none`) now fails verification and is routed into the existing `catch` block, returning the same `401 { error: 'Invalid or expired token' }` response the code already returns for any other invalid/expired token - no new response shape or status code is introduced.
- `ignoreExpiration` was already left at its default (`false`) and is unchanged; no other call arguments, return values, or control flow were touched.

## Verification

`node --check` was run against the fixed file (copied to a scratch location, not the case directory) and reported no syntax errors. The `algorithms` option and its array-of-strings shape come from the loaded `cwe/287/javascript/INDEX.md` guidance ("Always pass `{ algorithms: [...] }` explicitly to `jwt.verify()`") and match the `jsonwebtoken` `verify(token, secretOrPublicKey, options)` signature already in use in the original code (same three-argument call, only the options object added) - no new imports, packages, or unfamiliar APIs were introduced.
