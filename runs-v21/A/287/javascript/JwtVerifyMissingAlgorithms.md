## Verdict

Confirmed. The `jwt.verify()` call lacks an explicit `algorithms` constraint, allowing an attacker to forge authentication tokens by selecting an unexpected algorithm.

## Source

Line 21 in `authMiddleware.js`:
```javascript
const claims = jwt.verify(token, publicKey);
```

The absence of an `algorithms` option in the verification call leaves it vulnerable to algorithm substitution attacks. An attacker can craft a token using the `none` algorithm or a symmetric algorithm, bypassing the intended RS256 verification.

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

The fix adds `{ algorithms: ['RS256'] }` as the third argument to `jwt.verify()`. This restricts token verification to only accept tokens signed with the RS256 algorithm, which matches the asymmetric public key being used for verification.

Without this constraint, the jsonwebtoken library can be tricked into accepting:
- Tokens signed with the `none` algorithm (which bypasses signature verification entirely)
- Tokens signed with symmetric algorithms like HS256, which an attacker can forge if they know or can influence the verification key

By explicitly listing `['RS256']`, the middleware ensures that only tokens signed with the expected RSA private key are accepted, preventing algorithm substitution attacks.
