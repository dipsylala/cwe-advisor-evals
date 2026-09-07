## Verdict
Real vulnerability. `jwt.decode()` does not verify signatures and must not be used for authentication decisions.

## Source
`authHeader` from `req.headers['authorization']` (line 8) - attacker-controlled.

## Fix
Replace `jwt.decode()` with `jwt.verify()` to enforce signature validation, and explicitly pin the algorithm to prevent algorithm-confusion attacks. Wrap in try-catch to handle verification failures.

### File: authMiddleware.js

```javascript
// authMiddleware.js
// Express middleware that protects the internal admin API.
// Uses jsonwebtoken@9.0.2. jwt.verify() checks the signature against the
// supplied secret and rejects tokens that fail validation.
const jwt = require('jsonwebtoken');

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return res.status(500).json({ error: 'Server configuration error' });
    }

    const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });

    if (!payload || !payload.userId) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (payload.role !== 'admin') {
      return res.status(403).json({ error: 'Admin role required' });
    }

    req.user = { id: payload.userId, role: payload.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = { requireAdmin };
```

## Explanation
The original code called `jwt.decode(token)`, which only base64-decodes the payload without verifying the signature. This allowed an attacker to forge a token with any claims (e.g., `role: 'admin'`), and the middleware would trust it unconditionally.

The fix replaces this with `jwt.verify(token, secret, { algorithms: ['HS256'] })`, which:
1. Requires the signing secret from the environment (`JWT_SECRET`)
2. Verifies the token's signature against that secret
3. Explicitly specifies `algorithms: ['HS256']` to prevent algorithm-confusion attacks (e.g., a token signed with `alg: none` or a different algorithm)
4. Throws `JsonWebTokenError` on any verification failure, caught by the try-catch block

This ensures only tokens signed by the application are accepted, closing the authentication bypass.

## Behaviour changes
- Tokens are now cryptographically verified; forged or unsigned tokens are rejected with `401`
- Requires `JWT_SECRET` environment variable to be set; requests fail with `500` if missing
- Token expiration (`exp` claim) is now enforced by default if present
- Any tampering with token payload, signature, or algorithm selection is detected and rejected
- Response time is consistent for all invalid tokens (no early exit on verification failure)
