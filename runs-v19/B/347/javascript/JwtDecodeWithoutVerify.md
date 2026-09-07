## Verdict

CONFIRMED. The code uses `jwt.decode()` instead of `jwt.verify()`, which returns the JWT payload without validating the cryptographic signature. An attacker can forge an arbitrary JWT, set `role: 'admin'`, and bypass authorization checks at line 18.

## Source

User-controlled JWT from the Authorization header (`req.headers['authorization']`, line 8-9) flows to an unverified decode operation.

## Fix

### File: JwtDecodeWithoutVerify.js

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware that authorizes a request using the bearer token's claims.
app.use('/admin', (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Missing token');
  }

  // Read the verification key from configuration (must not come from the token).
  const secretKey = process.env.JWT_SECRET;
  if (!secretKey) {
    console.error('JWT_SECRET not configured');
    return res.status(500).send('Server configuration error');
  }

  // Verify the token signature with an explicit algorithms restriction.
  let claims;
  try {
    claims = jwt.verify(token, secretKey, {
      algorithms: ['HS256']  // Hardcoded, does not infer from token header
    });
  } catch (err) {
    // Signature verification failed - reject immediately.
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

The original code used `jwt.decode(token)` to extract the JWT payload without verifying the signature. This allows an attacker to forge any JWT by modifying the payload and resetting the signature to match. The middleware would trust the forged `role` claim and grant unauthorized admin access.

The fix replaces `jwt.decode()` with `jwt.verify(token, secretKey, { algorithms: ['HS256'] })`, which:
1. Validates the cryptographic signature against the server's secret key
2. Rejects any token with an invalid or missing signature
3. Uses an explicit, hardcoded `algorithms` array as defense-in-depth to prevent algorithm-confusion attacks (the token's header cannot override the verification algorithm)
4. Wraps the call in a try-catch to fail securely—any verification error immediately rejects the request with a 401 response

The verification key comes from `process.env.JWT_SECRET`, which is configuration-controlled and never derived from the untrusted token. The secret is validated at startup to prevent the weakness of an unset variable silently allowing forgery.

## Behaviour changes

- **New constraint**: Tokens must be signed with HMAC-SHA256 using the configured secret. Tokens using other algorithms or unsigned tokens are rejected.
- **New error handling**: Invalid tokens now return a 401 "Invalid token" response instead of silently trusting unauthenticated claims. This is the correct secure-fail behavior.
- **New configuration requirement**: The application now requires `JWT_SECRET` to be set in the environment. If missing, the server returns 500 and logs an error rather than processing requests. This forces the configuration error to be visible at startup.
- **Verification key sourcing**: The secret key is now always read from configuration, never from the token header or claims—this closes the algorithm-confusion vulnerability that would exist if the key source varied based on attacker input.

All other behavior is preserved: valid, properly signed tokens with `role: 'admin'` continue to grant access.
