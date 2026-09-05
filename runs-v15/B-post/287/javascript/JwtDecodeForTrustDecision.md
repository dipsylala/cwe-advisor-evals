## Verdict
exploitable

## Source
`token` extracted from the `Authorization` header at line 9

## Fix

**Vulnerable code:**
```javascript
const payload = jwt.decode(token);

if (!payload || !payload.userId) {
  return res.status(401).json({ error: 'Invalid token' });
}

if (payload.role !== 'admin') {
  return res.status(403).json({ error: 'Admin role required' });
}
```

**Fixed code:**
```javascript
let payload;
try {
  payload = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256']
  });
} catch (err) {
  return res.status(401).json({ error: 'Invalid token' });
}

if (!payload || !payload.userId) {
  return res.status(401).json({ error: 'Invalid token' });
}

if (payload.role !== 'admin') {
  return res.status(403).json({ error: 'Admin role required' });
}
```

## Explanation
The vulnerability occurs because `jwt.decode()` only performs base64 decoding of the JWT payload without verifying the signature. An attacker can forge any JWT payload and the middleware will trust it. The fix replaces `jwt.decode()` with `jwt.verify()`, which validates the signature using the secret key and ensures the token's algorithm matches the allowlist. The explicit `algorithms: ['HS256']` prevents algorithm-confusion attacks where an attacker might force the server to use a weaker algorithm. Error handling wraps the verify call in try-catch to catch `JsonWebTokenError` on signature failures, token expiry, or other validation failures, and returns `401` to reject the invalid token.

## Behaviour changes
The fixed code now performs cryptographic signature verification, which is a required security boundary that the original code lacked. The secret key (`process.env.JWT_SECRET`) must be configured in the deployment environment; if missing, `jwt.verify()` will throw an error that is caught and results in a `401`. The error handling is improved: any verification failure (invalid signature, wrong algorithm, expired token, malformed token) now returns `401` instead of potentially proceeding with unverified claims. The payload object returned by `jwt.verify()` is verified and trusted; subsequent role and userId checks operate on cryptographically validated data.
