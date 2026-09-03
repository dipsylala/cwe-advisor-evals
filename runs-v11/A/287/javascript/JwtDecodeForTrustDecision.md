## Verdict
CWE-287 (Improper Authentication) confirmed. The code uses `jwt.decode()` to extract and trust token claims without signature verification, allowing forged tokens to bypass authentication and authorization checks.

## Source
File: `authMiddleware.js`, Line 16

```javascript
const payload = jwt.decode(token);
```

The `jwt.decode()` function from jsonwebtoken performs only base64 decoding of the JWT payload and does NOT validate the signature. The code then uses the unverified payload to make authentication decisions at lines 22-24, trusting `payload.role` without any verification that the token was legitimately issued.

## Fix
Replace `jwt.decode()` with `jwt.verify()` to validate the token signature before trusting its claims:

```javascript
function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch (error) {
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
```

## Explanation
`jwt.verify()` validates the token's cryptographic signature using a secret key (for symmetric algorithms like HS256) or a public key (for asymmetric algorithms like RS256). This ensures the token was issued by a trusted authority and has not been tampered with.

The fix wraps `jwt.verify()` in a try-catch block to handle verification failures (invalid signature, expired token, malformed token) and returns a 401 response to reject unauthenticated requests.

The `algorithms` option restricts the accepted algorithms to HS256 (or the appropriate algorithm your application uses), preventing algorithm substitution attacks.

The `JWT_SECRET` should be stored securely in environment variables or a secrets management system, not hardcoded.
