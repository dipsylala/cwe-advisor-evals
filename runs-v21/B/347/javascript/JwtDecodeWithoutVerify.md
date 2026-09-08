## Verdict

The vulnerability is **confirmed and fixed**. The code uses `jwt.decode()`, which extracts the JWT payload without verifying the signature, allowing attackers to forge authentication tokens. The fix replaces `jwt.decode()` with `jwt.verify()`, adds an explicit `algorithms` array, and includes proper error handling.

## Source

The authorization middleware at line 16 extracts JWT claims from an untrusted Authorization header without verifying the signature. The `jwt.decode()` function performs no cryptographic validation—it merely decodes the Base64 payload, making it trivial for an attacker to forge tokens and bypass the role check at line 18.

```
Token source: req.headers['authorization'] → extract → jwt.decode(token) → trust claims
```

## Fix

### File: JwtDecodeWithoutVerify.js

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

// Middleware that authorizes a request using the bearer token's claims.
app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  try {
    // Verify the token's signature before trusting its claims
    const claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

    if (!claims || claims.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }

    req.user = claims;
    next();
  } catch (err) {
    return res.status(401).send('Invalid token');
  }
});

app.get('/admin/dashboard', (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}` });
});

module.exports = app;
```

## Explanation

The fix addresses CWE-347 by replacing `jwt.decode()` with `jwt.verify()`. The `verify()` function validates the token's cryptographic signature using the shared secret (read from `JWT_SECRET` at startup) before returning the claims. The explicit `algorithms: ['HS256']` array prevents algorithm confusion attacks where the attacker could specify a different algorithm in the token header.

The secret is read once at application startup and validated; if missing, the application fails immediately rather than silently accepting forged tokens at runtime. The try-catch wrapper ensures that any verification failure—invalid signature, expired token, missing required claims—triggers a 401 response, denying access to unsigned or tampered tokens.

## Behaviour changes

- **Startup validation:** The application now throws an error at startup if `JWT_SECRET` is not set, preventing misconfiguration
- **Signature verification:** All tokens must now have a valid signature; forged tokens are rejected with a 401 response
- **Algorithm enforcement:** Only HS256-signed tokens are accepted; tokens signed with other algorithms (RS256, "none", etc.) are rejected
- **Error handling:** Verification errors (invalid signature, expiration, missing claims) now result in a 401 response instead of granting access
- **Functional impact:** Legitimate tokens signed with the correct secret and algorithm continue to work; authorization logic remains unchanged

The fix preserves the original functionality for valid tokens while eliminating the signature bypass.
