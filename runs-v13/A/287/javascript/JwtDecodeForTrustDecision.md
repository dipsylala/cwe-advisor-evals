## Verdict
CONFIRMED

## Source
```javascript
const payload = jwt.decode(token);
```

Line 16 uses `jwt.decode()`, which performs no signature verification. An attacker can forge any JWT by simply base64-encoding a fake payload, and the code will accept it as valid because there is no cryptographic check.

## Fix
```javascript
let payload;
try {
  payload = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
} catch (err) {
  return res.status(401).json({ error: 'Invalid token' });
}

if (!payload || !payload.userId) {
  return res.status(401).json({ error: 'Invalid token' });
}
```

Replace `jwt.decode(token)` with `jwt.verify(token, secret)`, which validates the token's signature before returning the payload. Wrap the call in a try-catch block because `jwt.verify()` throws on invalid or expired tokens. Use a secret key from environment variables or configuration, never hardcode it.

## Explanation
`jwt.decode()` is a symmetric operation — it only base64-decodes the token payload without checking the signature. It is safe only for reading token metadata before verification (e.g., checking expiration), not for trust decisions.

`jwt.verify()` cryptographically validates that the token was signed by the holder of the secret key. It rejects:
- Tokens with invalid or missing signatures
- Tokens signed with a different key
- Tokens that have been tampered with
- Expired tokens (if `exp` claim is present)

By switching to `jwt.verify()`, the middleware now confirms that the token is authentic and from a trusted issuer before using the role and userId claims.
