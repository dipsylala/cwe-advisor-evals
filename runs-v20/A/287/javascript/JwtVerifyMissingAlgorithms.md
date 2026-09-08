## Verdict

Confirmed. `jwt.verify(token, publicKey)` is called without an `algorithms` option, so `jsonwebtoken` will accept whatever algorithm the token header declares rather than being pinned to the RS256 key that was actually loaded.

## Source

The token comes from the `Authorization` request header (`authHeader.split(' ')` on line 13, `token` used on line 21). It is fully attacker-controlled: a client can send any JWT, including one whose header claims a different signing algorithm than the one the server intends.

## Fix

### File: authMiddleware.js

```javascript
// authMiddleware.js
// Express middleware that authenticates API requests using an RS256-signed
// JWT. The RSA public key is loaded once at startup and used to verify the
// bearer token on every request. Targets jsonwebtoken 9.0.2.

const fs = require('fs');
const jwt = require('jsonwebtoken');

const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, 'utf8');

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    req.user = { id: claims.sub, roles: claims.roles || [] };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireAuth };
```

## Explanation

`jwt.verify()` in `jsonwebtoken` trusts the `alg` field inside the token's own header to decide how to validate the signature unless the caller restricts it with the `algorithms` option. The server here loads an RSA public key and intends RS256-only verification, but without `algorithms: ['RS256']` an attacker can craft a token with `alg: "HS256"` and sign it using the RSA public key text (which is public, e.g. served over TLS or embedded in client code) as the HMAC secret. `jsonwebtoken` will then verify that forged HMAC signature against the same public key value, treating it as a valid HMAC secret rather than an RSA public key, and the forged token passes verification — a classic algorithm-confusion authentication bypass. It also implicitly blocks the `alg: "none"` bypass, since only `RS256` is now accepted.

The fix constrains verification to the single expected algorithm, `RS256`, so a token whose header specifies any other algorithm (`HS256`, `none`, etc.) is rejected outright before signature checking, regardless of what the public key material looks like. This matches the key type actually provisioned (`JWT_PUBLIC_KEY_PATH`) and requires no change to how tokens are issued, since legitimate tokens are already signed with RS256.
