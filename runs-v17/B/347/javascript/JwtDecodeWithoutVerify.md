## Verdict

Exploitable

## Source

Token string from HTTP Authorization header (`req.headers['authorization']`), which is attacker-controlled. Extracted at line 9 by removing the "Bearer " prefix.

## Fix

### File: JwtDecodeWithoutVerify.js

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// Secret key for verifying JWT signatures (should come from secure configuration)
const SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware that authorizes a request using the bearer token's claims.
app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  try {
    // Fixed: Use jwt.verify() instead of jwt.decode() to verify the signature
    const claims = jwt.verify(token, SECRET, { algorithms: ['HS256'] });

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

The vulnerability at line 16 uses `jwt.decode(token)`, which decodes the JWT payload without verifying the cryptographic signature. An attacker can forge a JWT by crafting a payload with `role: 'admin'` and signing it with any key or omitting the signature entirely, and `jwt.decode()` will accept it. The fix replaces `jwt.decode()` with `jwt.verify(token, SECRET, { algorithms: ['HS256'] })`, which requires a valid signature computed with the server's secret key. The token is now rejected if the signature is invalid, forged, or missing. The explicit `algorithms: ['HS256']` array prevents algorithm confusion attacks where an attacker might declare a weaker or different algorithm in the token header. Error handling via try-catch rejects invalid tokens with a 401 response instead of crashing or allowing forged claims through.

## Behaviour changes

- **Added SECRET constant** (line 6): Defines the HMAC secret used for verification. Sourced from environment variable `JWT_SECRET` or a hardcoded fallback for development. Reason: `jwt.verify()` requires a key, which was missing from the original code.
- **Added try-catch block** (lines 20-33): Wraps the verification and authorization logic. `jwt.verify()` throws `JsonWebTokenError` on invalid signature, expired token, or malformed JWT; the catch handler returns 401 "Invalid token". Reason: Ensures failed verification is caught and rejected, rather than allowing an exception to propagate or returning undefined claims.
- **Added explicit algorithms array** (line 22): `{ algorithms: ['HS256'] }` restricts the token to HMAC with SHA-256. Reason: Prevents algorithm confusion where an attacker could declare `alg: 'none'` or switch to a public-key algorithm to bypass verification.
- **Return value from jwt.verify()** (line 22): Returns the decoded and verified claims object; identical contract to `jwt.decode()` for the authorization check on line 24. The difference is that `verify()` only returns if the signature is valid. Reason: Maintains the flow but with cryptographic assurance.

