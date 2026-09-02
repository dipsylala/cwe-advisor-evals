## Verdict

Exploitable. The code uses `jwt.decode()`, which decodes the JWT payload without verifying the signature. An attacker can forge a JWT with arbitrary claims (e.g., `role: 'admin'`) and bypass the authorization check.

## Source

The `token` extracted from the Authorization header (line 9) is attacker-controlled. An attacker can supply a forged JWT.

## Fix

**Vulnerable code:**
```javascript
const claims = jwt.decode(token);
```

**Fixed code:**
```javascript
let claims;
try {
  claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
} catch (err) {
  return res.status(401).send('Invalid token');
}
```

## Explanation

The fix replaces `jwt.decode()` with `jwt.verify()`, which cryptographically validates the token's signature before extracting claims. The explicit `algorithms: ['HS256']` array prevents algorithm confusion attacks (CVE-2015-9235 / GHSA-hjrf-2m68-5959). The verification key (`process.env.JWT_SECRET`) must be the same secret used to sign valid tokens. If verification fails, the middleware now rejects the request instead of proceeding with unverified claims.

## Behaviour changes

- **Verification key required**: The application must have `JWT_SECRET` configured. Tokens must be signed with this same secret for verification to succeed.
- **Explicit algorithm enforcement**: Only HS256 tokens are accepted; tokens claiming other algorithms (RS256, "none", etc.) are rejected.
- **Error handling**: Invalid, expired, or forged tokens now trigger an exception caught and handled as a 401 response. Previously, `jwt.decode()` would return the payload regardless of signature validity.
- **No silent acceptance**: Malformed JWTs that `jwt.decode()` might partially decode are now rejected outright.
