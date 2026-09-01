## Verdict

Real vulnerability confirmed. The code uses `jwt.decode()` which decodes the JWT payload without verifying the signature. An attacker can forge or modify the token payload, including setting `role: 'admin'` without possession of the signing key, and bypass the authorization check.

## Source

The vulnerability is at line 16 of JwtDecodeWithoutVerify.js:
```javascript
const claims = jwt.decode(token);
```

`jwt.decode()` returns the decoded payload without signature verification. The token originates from the HTTP Authorization header (line 9, attacker-controlled), and the decoded claims are used directly for access control (line 18: `claims.role !== 'admin'`).

## Fix

Replace `jwt.decode()` with `jwt.verify()`, add the signing secret, and include an explicit `algorithms` array:

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// Signing secret should come from secure configuration, not hardcoded
const JWT_SECRET = process.env.JWT_SECRET;

app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  try {
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

`jwt.decode()` only decodes the payload without checking the signature. An attacker can create a forged JWT with any payload. The fix replaces it with `jwt.verify()`, which cryptographically validates the signature using the shared secret (`JWT_SECRET`). The explicit `algorithms: ['HS256']` array prevents algorithm confusion attacks where a token claims a different algorithm in its header. A try-catch block handles verification failures (including tokens with invalid signatures) and returns a 401 response, denying access. The secret must be stored securely in configuration (e.g., environment variable) and never hardcoded.

## Behaviour changes

- **Before**: Accepts any JWT regardless of signature validity.
- **After**: Only accepts valid tokens signed with the configured secret. Invalid or forged tokens are rejected with a 401 response.
- **Side effect**: Legitimate tokens that are not signed with the configured secret will now be rejected. Configuration must ensure the same secret is used to sign tokens and verify them.
