## Verdict

Confirmed. `requireAdmin` calls `jwt.decode(token)`, which only base64-decodes the JWT payload and never checks the token's signature, expiry, or issuer. Anyone can craft an unsigned or arbitrarily-signed token with `{"userId": "...", "role": "admin"}` in the payload and be granted admin access, since the middleware trusts whatever claims come back.

## Source

`req.headers['authorization']` (the `Bearer <token>` value) flows unauthenticated into `jwt.decode(token)` at line 16, and the resulting `payload.userId` / `payload.role` are then used directly for authentication (`payload.userId`) and authorization (`payload.role !== 'admin'`) decisions with no cryptographic verification in between.

## Fix

### File: authMiddleware.js
```javascript
// authMiddleware.js
// Express middleware that protects the internal admin API.
// Uses jsonwebtoken@9.0.2. jwt.verify() checks the signature, expiry, and
// (when configured) issuer/audience before the payload can be trusted.
const jwt = require('jsonwebtoken');

// Secret/public key used to verify tokens issued by the auth service.
// Must be provisioned via environment/secret manager, not hard-coded.
const JWT_SECRET = process.env.JWT_SECRET;

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  let payload;
  try {
    // Verify signature, expiry, and pin the accepted algorithm so an
    // attacker cannot supply an unsigned ("none") or otherwise weaker
    // token type and have it accepted.
    payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (!payload || !payload.userId) {
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

`jwt.decode()` in `jsonwebtoken` is a pure base64url decode of the header and payload segments; it never touches the signature segment, so it cannot distinguish a token issued by the real authorization server from one an attacker forged locally with the same shape. The fix replaces it with `jwt.verify(token, secret, { algorithms: [...] })`, which recomputes the signature over the header and payload using the server's own key and rejects the token (throwing) if it does not match, and also rejects an expired token (`exp`) automatically.

Pinning `algorithms` explicitly is required alongside the switch to `verify`: without it, an attacker who can influence the `alg` header can attempt an algorithm-confusion attack (e.g. against an RS256-issuing service, submitting an HS256 token signed with the public key). Restricting `algorithms` to the single algorithm actually used to issue these tokens (`HS256` for a shared-secret setup; use `{ algorithms: ['RS256'] }` with the issuer's public key if tokens are asymmetrically signed) closes that off.

The verification failure path is wrapped in try/catch because `jwt.verify()` throws (`JsonWebTokenError`, `TokenExpiredError`, etc.) rather than returning `null` the way `jwt.decode()` does on a malformed token; any thrown error is treated as an invalid token and produces the same 401 response the caller already expects on a bad token, so the response contract for callers is unchanged. Downstream checks (`payload.userId`, `payload.role`) are left in place since the payload structure itself has not changed - only its trustworthiness now depends on a verified signature.
