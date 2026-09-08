## Verdict

Confirmed. The `/admin` authorization middleware calls `jwt.decode(token)`, which only base64-decodes the JWT payload and never checks the token's signature. Any caller can forge a token with an arbitrary header and payload (e.g. `{"role":"admin"}`), and this middleware will accept it as authentic, granting admin access.

## Source

The attacker-controlled input is the `Authorization` request header (`req.headers['authorization']`), read on line 8 and stripped of its `Bearer ` prefix on line 9. This `token` value flows unmodified into `jwt.decode(token)` on line 16, whose result (`claims`) is trusted for the authorization decision on line 18 and attached to `req.user` on line 22.

## Fix

### File: JwtDecodeWithoutVerify.js

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable must be set');
}

// Middleware that authorizes a request using the bearer token's claims.
app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  let claims;
  try {
    claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
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

`jsonwebtoken`'s `decode()` performs no cryptographic verification at all - it is documented as an unsafe, non-verifying decode intended only for inspecting a token you already trust. `verify()` is the API that actually checks the signature against a known key and rejects a tampered or forged token by throwing.

The fix replaces `jwt.decode(token)` with `jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })` wrapped in a try/catch, since `verify()` throws (rather than returning `null`) on a bad signature, expired token, or malformed input. Explicitly pinning `algorithms: ['HS256']` closes the classic algorithm-confusion bypass where an attacker sets `alg: "none"` (or a mismatched algorithm) in the token header to skip signature checking entirely - without this option, `verify()` would accept whatever algorithm the attacker-supplied header names. The secret itself is pulled from an environment variable rather than hardcoded, and the middleware fails closed (throws at startup) if it is missing, so the service cannot silently run with an empty or undefined verification key.
