## Verdict

The finding is **confirmed**. Line 16 uses `jwt.decode(token)` which does not verify the cryptographic signature. This allows an attacker to forge any JWT claim (including `role: 'admin'`) and bypass the role-based access control check at line 18, gaining unauthorized admin access.

## Source

- **Location**: evals/cases/347/javascript/JwtDecodeWithoutVerify/JwtDecodeWithoutVerify.js, line 16
- **Source**: `token` extracted from the authorization header at line 9
- **Taint flow**: Header → Token (line 9) → `jwt.decode(token)` (line 16) → Authorization decision (line 18)

## Fix

**Vulnerable code (line 16):**
```javascript
const claims = jwt.decode(token);
```

**Fixed code:**
```javascript
const secret = process.env.JWT_SECRET; // Verification key from configuration
if (!secret) {
  return res.status(500).send('JWT secret not configured');
}

let claims;
try {
  claims = jwt.verify(token, secret, { algorithms: ['HS256'] });
} catch (err) {
  return res.status(401).send('Invalid or expired token');
}
```

**Assumptions:**
- The JWT secret is stored in the `JWT_SECRET` environment variable (a common configuration pattern).
- The tokens are signed with HMAC SHA-256 (`HS256`). If RSA (`RS256`) or another algorithm is used, adjust the `algorithms` array and provide the corresponding public key.
- The application should fail securely when the secret is not configured (preventing silent bypass).

## Explanation

`jwt.decode()` returns the payload without checking the signature—the entire cryptographic verification step is skipped. An attacker can craft a token with any claims and `decode()` will happily return those claims as if they were valid.

`jwt.verify(token, secret, { algorithms: ['HS256'] })` performs actual signature verification using the provided secret and the specified algorithm(s). It will throw a `JsonWebTokenError` if:
- The signature is invalid or missing
- The token is expired
- The algorithm in the token header does not match the allowed algorithms array

The fix wraps verification in a try-catch to handle errors gracefully, rejecting the request with a 401 status on any verification failure. The explicit `algorithms` array is a defense-in-depth measure: it prevents algorithm-confusion attacks where an attacker tries to trick the library into accepting a weaker or no-signature algorithm.

The verification secret must come from secure configuration (environment variable, keystore, or JWKS endpoint), never from the token itself. Here it is read once from `process.env.JWT_SECRET` before verification.

## Behaviour changes

1. **Requests with forged or unsigned tokens will now be rejected** - Previously accepted because signature was never checked; now validation fails and returns HTTP 401.
2. **Expired tokens will be rejected** - `jwt.verify()` checks token expiration by default; `jwt.decode()` ignores it.
3. **Tokens signed with unexpected algorithms will be rejected** - The hardcoded `algorithms: ['HS256']` restricts the accepted signature algorithm, preventing algorithm-confusion attacks.
4. **Missing or misconfigured JWT secret will cause a 500 error** - The application will not silently bypass authentication if the secret is not set (fail-secure behavior).
5. **Performance impact is negligible** - Signature verification adds microseconds and is necessary security cost.
