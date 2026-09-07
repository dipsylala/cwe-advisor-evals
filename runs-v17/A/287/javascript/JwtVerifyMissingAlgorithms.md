## Verdict

CONFIRMED. The `jwt.verify()` call on line 21 lacks the `algorithms` option, allowing an attacker to perform an algorithm-confusion attack (e.g. switching from RS256 to HS256) or accept unsigned tokens with `alg: none`, bypassing authentication entirely.

## Source

authMiddleware.js, line 21: `jwt.verify(token, publicKey)` called without an `algorithms` option.

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
    // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
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

The fix adds `{ algorithms: ['RS256'] }` as the third argument to `jwt.verify()`, explicitly pinning the allowed signing algorithm to RS256. This prevents algorithm-confusion attacks where an attacker could:

1. Re-sign the token with HS256 using the public key as the HMAC secret, causing `jsonwebtoken` to accept it
2. Submit a token with `alg: none` to bypass signature verification entirely
3. Switch to any other algorithm the library supports

By restricting verification to only RS256, the token's algorithm header must match the configuration, and any mismatch (including `none`) causes `jwt.verify()` to throw an error, which is caught and returns a 401 response.

