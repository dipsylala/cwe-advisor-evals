## Verdict

Exploitable. The `jwt.verify()` call on line 21 lacks the required `algorithms` option, allowing an attacker to perform an algorithm-confusion attack by crafting a token with `alg: none`, `alg: HS256` (when RS256 is expected), or other mismatched algorithms. Without an explicit algorithm allowlist, `jsonwebtoken` infers the algorithm from the token header, trusting attacker-controlled data.

## Source

The vulnerability lies at line 21 in authMiddleware.js, where `jwt.verify(token, publicKey)` is called without pinning the allowed signing algorithms. The token is attacker-controlled via the `Authorization` header and reaches the sink unfiltered.

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

The fix adds an explicit `algorithms` option to `jwt.verify()` on line 21, pinning verification to RS256 only. This prevents algorithm-confusion attacks where an attacker could substitute a weaker algorithm (`alg: none`, `alg: HS256`) to forge a valid token. By matching the algorithm the issuer actually uses to sign tokens, the middleware rejects any token that deviates from that contract, even if the signature is cryptographically valid under a different algorithm.

## Behaviour changes

None. The fix preserves the existing contract: `jwt.verify()` still returns the decoded claims on success and throws `JsonWebTokenError` on failure (invalid signature, expired token, or now, mismatched algorithm). The error is caught identically at line 24-26 and returns a 401 to the caller. The only change is that tokens with a different algorithm are now rejected instead of accepted, which is the correct and intended behaviour for this endpoint.

Verification: `node --check` passed on the fixed code with no syntax errors.
