## Verdict

Exploitable. The middleware uses `jwt.decode()`, which performs no signature verification. An attacker can forge a JWT token with any `userId` and `role: 'admin'` claims, and the middleware will accept it unconditionally.

## Source

The `token` value extracted from the `Authorization` header on line 9:
```javascript
const [scheme, token] = authHeader.split(' ');
```
This is entirely attacker-controlled; the header is supplied by the HTTP request client.

## Fix

Replace `jwt.decode()` with `jwt.verify()`, providing a secret key and an explicit algorithm allowlist. The middleware must also handle verification errors.

**Vulnerable code:**
```javascript
const payload = jwt.decode(token);

if (!payload || !payload.userId) {
  return res.status(401).json({ error: 'Invalid token' });
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

if (!payload.userId) {
  return res.status(401).json({ error: 'Invalid token' });
}
```

## Explanation

`jwt.decode()` only base64-decodes the JWT payload and performs no cryptographic signature verification. An attacker can forge any token with any claims and the middleware will trust it. The fix replaces `jwt.decode()` with `jwt.verify()`, which validates the token signature using the server's secret key stored in `JWT_SECRET`. By explicitly passing `algorithms: ['HS256']`, the middleware prevents algorithm-confusion attacks where a token could claim to use a different algorithm in its header. The try-catch block now properly handles invalid or tampered tokens by returning `401`, since `jwt.verify()` throws `JsonWebTokenError` rather than returning null.

## Behaviour changes

1. **Token verification now enforced** - Invalid signatures cause `jwt.verify()` to throw; previously `jwt.decode()` would accept any base64-decodable input.
2. **Expiry now checked by default** - `jwt.verify()` enforces the `exp` claim if present; `jwt.decode()` ignored it.
3. **Requires `JWT_SECRET` environment variable** - The secret key must be available at runtime; previously the code had no key requirement.
4. **Error handling changed** - Now catches exceptions from `jwt.verify()`; the original `!payload` check at line 18 would never catch the error since decode returns an object for any valid base64 structure.
5. **Null check simplified** - The `!payload` check at line 18 is removed since `jwt.verify()` throws on any failure rather than returning null; only the `payload.userId` check remains.
