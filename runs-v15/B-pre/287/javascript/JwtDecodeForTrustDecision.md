## Verdict

Confirmed improper authentication. Line 16 calls `jwt.decode()`, which performs no signature verification and returns only the base64-decoded payload. An attacker can forge a token with arbitrary claims (`userId`, `role`) and the middleware will accept it as authentic, granting unauthorized access.

## Source

File: `evals/cases/287/javascript/JwtDecodeForTrustDecision/authMiddleware.js`

```javascript
// Line 15-16: Vulnerable code
const payload = jwt.decode(token);
```

The token originates from the `Authorization` header (line 8), an attacker-controlled source. The `jwt.decode()` call applies no cryptographic verification before the payload is trusted for authentication and authorization decisions (lines 18-26).

## Fix

Replace `jwt.decode()` with `jwt.verify()`, which validates the token signature and expiry before returning the payload. Pass an explicit `algorithms` allowlist to prevent algorithm substitution attacks.

**Fixed code:**

```javascript
const jwt = require('jsonwebtoken');

// Define the secret used to sign tokens (should be stored securely, outside source control)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    // Use jwt.verify() instead of jwt.decode() to validate signature and expiry
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

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

`jwt.decode()` performs only base64 decoding of the token payload—it never validates the signature. An attacker can construct a token with arbitrary claims (e.g., `{"userId": "123", "role": "admin"}`) and any or no signature, and the application will treat it as legitimate.

`jwt.verify()` cryptographically validates the signature using the secret key and enforces expiry checks before returning the payload. The explicit `algorithms: ['HS256']` prevents algorithm-confusion attacks where an attacker might attempt to switch the token to an unsigned algorithm (like `alg: none`) or a different family.

The try-catch block safely handles verification failures (invalid signature, expired token, malformed token) and returns a `401` Unauthorized status, which is the correct HTTP response for failed authentication.

## Behaviour changes

- **Added signature validation**: Tokens are now cryptographically verified against the server secret before any claims are trusted.
- **Added expiry enforcement**: Expired tokens are rejected; `jwt.verify()` checks the `exp` claim by default.
- **Added error handling**: Failed verification (invalid signature, expired, malformed) is caught and returns `401` instead of crashing or using undefined payload.
- **Changed return status on token failure**: Token verification failures now return `401 Unauthorized` with a generic error message, preventing information leakage about which part of the token was invalid.
- **Requires JWT secret**: The application now depends on a server-side secret (`JWT_SECRET`) for verification. This must be stored securely (e.g., environment variable) and shared only with the issuing server. Rotating this secret invalidates all issued tokens.
