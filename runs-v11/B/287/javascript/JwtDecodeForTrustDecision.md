## Verdict

Authentication bypass via unsigned JWT decode. The code accepts any JWT payload without verifying the signature, allowing an attacker to forge identity claims.

## Source

Line 16: `const payload = jwt.decode(token);`

The `jwt.decode()` function from `jsonwebtoken` performs only base64 decoding of the JWT payload. It does not validate the signature, HMAC, or any cryptographic claim. Any token structure with a valid base64-encoded payload will be accepted, even if unsigned or signed with an unknown key.

## Fix

Replace `jwt.decode()` with `jwt.verify()` and provide the signing key and an explicit algorithm allowlist:

```javascript
const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
```

This verifies:
1. The signature is valid for the signing key
2. The algorithm matches the allowlist (prevents algorithm-confusion attacks)
3. Throws `JsonWebTokenError` if verification fails, preventing the code from reaching the null-check on line 18

The full corrected middleware:

```javascript
const jwt = require('jsonwebtoken');

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });

    if (!payload.userId) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (payload.role !== 'admin') {
      return res.status(403).json({ error: 'Admin role required' });
    }

    req.user = { id: payload.userId, role: payload.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = { requireAdmin };
```

Key changes:
- Replace `jwt.decode()` with `jwt.verify()`
- Pass `process.env.JWT_SECRET` (or equivalent key management) as the second argument
- Require `algorithms: ['HS256']` (or whichever algorithm(s) the issuer actually uses) to prevent token header injection
- Wrap in try-catch to handle `JsonWebTokenError` on invalid/expired tokens
- Simplify the payload check since `null` checks are redundant after successful verification

## Explanation

CWE-287 (Improper Authentication) occurs when authentication logic is bypassed or incomplete. In this case, the verify callback never checks the JWT signature.

`jwt.decode()` is a plain base64 decoder for debugging. It decodes the token payload without validating:
- The signature (HMAC or RSA signature verification)
- The signing algorithm (vulnerable to algorithm-confusion attacks)
- Expiry or other claims

An attacker can craft a token with any payload (e.g., `{ userId: "admin", role: "admin" }`), and since the code never verifies the signature, it is accepted as authentic. This grants unauthorized access.

`jwt.verify()` performs cryptographic signature verification. It requires:
1. A secret key (symmetric HMAC) or public key (asymmetric RSA/ECDSA)
2. An explicit algorithm allowlist to reject unexpected algorithm headers
3. A match between the token's signature and the key material

If verification fails, it throws an exception, halting execution before the payload is trusted.

## Behaviour changes

**Before (vulnerable):**
- Any caller can forge a token with arbitrary claims (userId, role, etc.)
- Admin access is granted on any token with `role: 'admin'` regardless of signature
- Only the presence of keys in the payload matters, not cryptographic proof of origin

**After (fixed):**
- Only tokens signed by the server's secret key are accepted
- Forged tokens are rejected with `401 Unauthorized`
- Algorithm confusion attacks (alg: none, algorithm swaps) are blocked by the explicit allowlist
- Expired tokens are rejected if `exp` is present and in the past
- The code fails safely: invalid tokens result in a catch-block return of 401, not a bypass
