## Verdict

Exploitable. The code uses `jwt.decode(token)` which performs no signature verification, allowing an attacker to forge arbitrary tokens and bypass authorization checks.

## Source

Attacker-controlled JWT from the `Authorization` header (line 8-9), passed to the authentication middleware.

## Fix

**Vulnerable code (line 16):**
```javascript
const claims = jwt.decode(token);
```

**Fixed code:**
```javascript
let claims;
try {
  claims = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256']
  });
} catch (err) {
  return res.status(401).send('Invalid token');
}
```

## Explanation

`jwt.decode()` extracts the payload without verifying the cryptographic signature, allowing an attacker to forge a token with arbitrary claims (including `role: 'admin'`). The fix replaces it with `jwt.verify()`, which validates the signature using a hardcoded secret and explicit algorithm restriction before returning the claims. The explicit `algorithms` array prevents algorithm confusion attacks even if the library's key-type inference were to change. The try-catch block handles verification failures (invalid signature, expired token, etc.) and rejects them with a 401 response instead of proceeding with unverified claims.

## Behaviour changes

1. **Error handling added**: `jwt.verify()` throws `JsonWebTokenError` on signature mismatch or expiration; the original code did not check for this. The fix catches these errors and returns 401, preventing unauthorized access.
2. **Secret retrieval**: Assumes `JWT_SECRET` is available in `process.env`. This environment variable must be set during deployment; if missing, verification will fail. This is the correct pattern and a necessary behaviour change to close the vulnerability.
3. **Algorithm restriction**: Specifies `algorithms: ['HS256']` to prevent algorithm confusion. The original code had no algorithm control.
4. **Token expiration checking**: `jwt.verify()` checks `exp` claim by default; the original decode did not, allowing expired tokens to pass authorization checks.
