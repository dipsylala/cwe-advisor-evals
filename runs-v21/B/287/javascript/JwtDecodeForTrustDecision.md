## Verdict

The code uses `jwt.decode(token)` on line 16 to extract claims, then trusts those claims for an authorization decision (role check). `jwt.decode()` performs no signature verification—it is a plain base64 decode. An attacker can forge a token with any payload and have it accepted. Replace `jwt.decode()` with `jwt.verify()` and provide the signing secret and an explicit algorithm allowlist.

## Source

**CWE-287: Improper Authentication**

**File:** `authMiddleware.js`, line 16

**Vulnerability:** The `jwt.decode()` call trusts an unverified JWT payload for an authorization check at lines 22–24, allowing any forged token.

**Root cause:** `jwt.decode()` in the `jsonwebtoken` package only base64-decodes the payload and does not check the signature. Calling it in an authentication or authorization context makes the application accept any token structure.

## Fix

### File: authMiddleware.js

```javascript
// authMiddleware.js
// Express middleware that protects the internal admin API.
// Uses jsonwebtoken@9.0.2. jwt.decode() never checks a signature at any
// version of this package - it is a plain base64 decode of the payload.
const jwt = require('jsonwebtoken');

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  // Use jwt.verify() with explicit algorithm pinning to validate the signature.
  // The JWT_SECRET must be stored in environment variables, never hard-coded.
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'Server configuration error' });
  }

  let payload;
  try {
    payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
  } catch (err) {
    // jwt.verify() throws on invalid signature, expired token, or malformed JWT.
    return res.status(401).json({ error: 'Invalid or expired token' });
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

The vulnerability is that `jwt.decode()` performs no signature verification. An attacker can craft a JWT with any payload (e.g., `{ userId: 1, role: 'admin' }`) and sign it with any key (or no key, using `alg: none` if the library allows it). The original code would accept it and grant admin access.

The fix:
1. Replace `jwt.decode()` with `jwt.verify(token, secret, { algorithms: ['HS256'] })`
2. Provide the signing secret from an environment variable (never hard-coded)
3. Use explicit algorithm pinning (`algorithms: ['HS256']`) to prevent algorithm-confusion attacks where an attacker changes the token's `alg` header to bypass verification
4. Wrap the verification in a try-catch to handle errors gracefully (expired tokens, invalid signatures, malformed JWTs) and return `401` in all cases
5. Add a check that the secret is configured, returning `500` if missing (configuration error, not auth failure)

The algorithm `['HS256']` assumes HMAC with SHA-256 is the signing method. If your application uses RSA (RS256) or ECDSA (ES256), replace the algorithm in the options accordingly, but always pass an explicit allowlist rather than relying on the token's header to select the algorithm.

## Behaviour changes

- **Before:** Any JWT structure with a Bearer scheme is accepted and its payload is trusted for authorization.
- **After:** Only JWTs signed with the server's secret using HS256 are accepted. Forged tokens are rejected with `401 Unauthorized`.
- **Side effect:** If the `JWT_SECRET` environment variable is not set, the application returns `500 Internal Server Error` instead of attempting to verify. Ensure the secret is configured in your deployment.
- **Timing:** Verification now includes cryptographic operations (HMAC computation), which has negligible overhead on modern systems but is slightly slower than base64 decode alone.
- **Error handling:** All invalid tokens (wrong signature, expired, malformed) now return the same generic `401` message, preventing user enumeration via error details.
