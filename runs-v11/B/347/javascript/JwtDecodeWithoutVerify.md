## Verdict

exploitable

## Source

`req.headers['authorization']` (line 8) - attacker-controlled HTTP request header

## Fix

**Vulnerable Code:**
```javascript
const claims = jwt.decode(token);

if (!claims || claims.role !== 'admin') {
  return res.status(403).send('Forbidden');
}
```

**Fixed Code:**
```javascript
let claims;
try {
  claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
} catch (error) {
  return res.status(401).send('Invalid token');
}

if (!claims || claims.role !== 'admin') {
  return res.status(403).send('Forbidden');
}
```

## Explanation

The vulnerability occurs because `jwt.decode()` extracts the payload without verifying the cryptographic signature. This allows an attacker to forge a JWT with arbitrary claims (such as `role: 'admin'`) and bypass the authorization check. The fix replaces `jwt.decode()` with `jwt.verify()`, which cryptographically validates the token's signature using a shared secret before returning the claims. An explicit `algorithms` array is passed to prevent algorithm confusion attacks and to ensure only HMAC-SHA256 tokens are accepted. The fix also wraps verification in a try-catch block to properly reject tokens with invalid signatures, expired tokens, or other verification failures, returning a 401 status instead of proceeding with unverified claims.

## Behaviour changes

- **Error handling added:** Verification failures (invalid signature, expired token, malformed token) now return 401 instead of potentially processing unverified claims. Original code had no error handling for `jwt.decode()`.
- **Secret key required:** Fix assumes `JWT_SECRET` is available in environment variables. This must be configured securely before deployment.
- **Algorithm restriction added:** Only HS256 tokens are accepted. Assumption: the application uses HMAC-SHA256 for token signing. If using RSA or another algorithm, update `algorithms` array accordingly (e.g., `['RS256']`).
- **jsonwebtoken version requirement:** Assumes `jsonwebtoken` 9.0.0 or later for reliable algorithm handling; earlier versions require explicit hardening.
