## Verdict

**Confirmed**: CWE-287 (Improper Authentication) - JWT verification missing algorithm constraint.

The code calls `jwt.verify()` without pinning the allowed signing algorithms, allowing an attacker to submit a token signed with a different algorithm (e.g., `alg: none` or `HS256` instead of `RS256`) and potentially bypass authentication.

## Source

File: `authMiddleware.js`, line 21

```javascript
const claims = jwt.verify(token, publicKey);
```

The `token` is extracted from the `Authorization` header (attacker-controlled) and passed directly to `jwt.verify()` without algorithm validation.

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

The fix adds `{ algorithms: ['RS256'] }` as the third argument to `jwt.verify()`. This explicitly pins the signing algorithm to RSA with SHA-256, matching the token issuance documented in the code comments. With this option set, `jsonwebtoken` rejects any token bearing a different `alg` claim in its header—preventing algorithm-confusion attacks where an attacker supplies a token with `alg: none` or `alg: HS256` and attempts to bypass the signature check. The error handling remains unchanged: any verification failure (wrong algorithm, bad signature, expired token) throws `JsonWebTokenError`, caught and returned as `401`.

## Behaviour changes

- **Before**: Tokens with any signing algorithm accepted if signature verification succeeds with the provided key (algorithm inferred from header).
- **After**: Only tokens with `alg: RS256` are accepted; any other algorithm in the token header causes verification to fail with a thrown error and returns `401`.
- **No breaking changes**: Legitimate RS256-signed tokens continue to verify and authenticate correctly; only malformed or algorithm-swapped tokens are now rejected (the intended behaviour).
