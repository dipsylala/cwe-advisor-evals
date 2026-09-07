## Verdict
CONFIRMED — The code uses `jwt.decode()` which decodes the JWT without verifying its cryptographic signature. An attacker can forge any JWT token with arbitrary claims (e.g., `role: 'admin'`) since the signature is never validated.

## Source
```javascript
const claims = jwt.decode(token);

if (!claims || claims.role !== 'admin') {
  return res.status(403).send('Forbidden');
}
```

The vulnerability is at line 16: `jwt.decode(token)` accepts and trusts any token regardless of signature validity, then authorizes the request based on unverified claims.

## Fix
Replace `jwt.decode(token)` with `jwt.verify(token, secret)` and wrap in a try-catch to handle invalid tokens:

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const secret = process.env.JWT_SECRET || 'your-secret-key';

app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  let claims;
  try {
    claims = jwt.verify(token, secret);
  } catch (err) {
    return res.status(401).send('Invalid token');
  }

  if (!claims || claims.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }

  req.user = claims;
  next();
});

app.get('/admin/dashboard', (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}` });
});

module.exports = app;
```

## Explanation
`jwt.decode()` is unsafe because it only decodes the payload without verifying the signature. An attacker can create a forged token with any claims and the application will trust it.

`jwt.verify()` cryptographically validates the signature using the shared secret before returning the claims. If verification fails (invalid signature, expired token, etc.), it throws an error, which is caught and rejected with a 401 status.

The secret should be stored securely (e.g., environment variable or key management system), not hardcoded. All JWT verification must go through `jwt.verify()` with the correct secret before trusting any claims in the token.
