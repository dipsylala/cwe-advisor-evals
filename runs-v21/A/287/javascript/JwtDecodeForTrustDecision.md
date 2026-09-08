## Verdict
The code uses `jwt.decode()` to extract and trust JWT claims without verifying the signature. An attacker can forge any JWT with arbitrary claims (e.g., `role: 'admin'`) since the function performs no cryptographic validation. This is a critical authentication bypass.

## Source
Line 16 calls `jwt.decode(token)`, which the package documentation and inline comment confirm performs only base64 decoding with no signature verification. The resulting payload is immediately trusted to determine access control (checking `role === 'admin'` on line 22).

## Fix
### File: authMiddleware.js
```javascript
// authMiddleware.js
// Express middleware that protects the internal admin API.
// Uses jsonwebtoken@9.0.2. jwt.decode() never checks a signature at any
// version of this package - it is a plain base64 decode of the payload.
const jwt = require('jsonwebtoken');

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    // Use jwt.verify() to validate the signature with the secret key
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (!payload || !payload.userId) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (payload.role !== 'admin') {
      return res.status(403).json({ error: 'Admin role required' });
    }

    req.user = { id: payload.userId, role: payload.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireAdmin };
```

## Explanation
The fix replaces `jwt.decode()` with `jwt.verify(token, process.env.JWT_SECRET)`, which cryptographically validates the signature using the secret key. Any tampered or forged token will fail verification.

Key changes:
1. `jwt.verify()` instead of `jwt.decode()` — performs signature validation, not just decoding
2. Secret key from `process.env.JWT_SECRET` — provides the key for signature verification (must be set securely in production)
3. Try-catch wrapper — catches `TokenExpiredError`, `JsonWebTokenError`, and other errors, returning 401 for any verification failure
4. Single error message on catch — treats all verification failures uniformly, preventing information disclosure

The payload is now trusted only after cryptographic verification, closing the authentication bypass.
