## Verdict
The vulnerability is a real authentication bypass. The code uses `jwt.decode()` to extract and trust JWT claims without verifying the signature, allowing attackers to forge tokens with arbitrary role claims.

## Source
Line 16 in authMiddleware.js uses `jwt.decode(token)`, which only performs base64 decoding without cryptographic verification. The attacker-controlled `token` parameter reaches this sink unchecked, and its payload claims (especially `role`) are trusted for authorization decisions at lines 22–24.

## Fix

### File: authMiddleware.js

```javascript
// authMiddleware.js
// Express middleware that protects the internal admin API.
// Uses jsonwebtoken@9.0.2. jwt.verify() checks the signature against a secret.
const jwt = require('jsonwebtoken');

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  // Verify the token signature using the server's secret key.
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
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
The fix replaces `jwt.decode()` with `jwt.verify()`, which validates the token's HMAC signature against a server-held secret (`process.env.JWT_SECRET`). This ensures:

1. **Signature verification**: The token was issued by the server; an attacker cannot forge a token with an arbitrary role.
2. **Integrity**: The payload has not been tampered with since issuance.
3. **Failure handling**: Any signature mismatch, expiration, or malformed token throws an error caught by the try-catch block, returning a 401 response.

The authentication decision at line 22–24 now relies on cryptographically verified claims rather than unverified base64-decoded data.
