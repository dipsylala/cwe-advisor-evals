## Verdict

Confirmed. The `/admin` middleware calls `jwt.decode(token)`, which parses the JWT payload without checking the token's signature. Any caller can forge a token with an arbitrary payload (base64-encode a header and a `{"role":"admin"}` body, append any trailing segment as the "signature") and `jwt.decode` will happily return those claims. The subsequent authorization check (`claims.role !== 'admin'`) then trusts attacker-controlled data, letting an unauthenticated or unprivileged caller reach `/admin/dashboard`.

## Source

`req.headers['authorization']` on line 8, stripped of the `Bearer ` prefix into `token` on line 9. This is fully attacker-controlled input.

## Fix

```js
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// Load from configuration/secret storage, never hardcode.
const JWT_SECRET = process.env.JWT_SECRET;

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

`jwt.decode()` in the `jsonwebtoken` package is explicitly documented as performing no signature or expiration verification - it is a base64 decode, not an authentication check. Trusting its output for an authorization decision means the signature is never actually validated, which is the definition of CWE-347.

The fix replaces `jwt.decode(token)` with `jwt.verify(token, secret, options)`, which cryptographically validates the signature against a known key before returning claims, and throws if the signature is invalid, the token is expired, or (with the `algorithms` option supplied) the token uses an algorithm other than the one explicitly allowed.

The explicit `algorithms: ['HS256']` option (adjust to the algorithm actually used to sign these tokens, e.g. `RS256` with a public key) is required, not optional hardening: without it, `jwt.verify` will accept whatever algorithm the token header declares, including `alg: none` in older configurations or a mismatched algorithm that can enable key-confusion attacks where a public key meant for RS256 verification is misused as an HMAC secret. Pinning the algorithm closes that gap.

The secret (or public key, for asymmetric signing) must come from secure configuration - an environment variable or secret manager - never be hardcoded, and must be the same key used to sign the tokens in the first place. Wrapping the call in try/catch and returning 401 on failure ensures a forged or expired token is rejected before any claims are trusted, rather than silently falling through with `claims` set to attacker data.
