# CWE-287: Improper Authentication

## Verdict

CONFIRMED. The `jwt.verify()` call on line 21 omits the `algorithms` option, allowing algorithm-confusion attacks where an attacker can re-sign a token with a different algorithm (e.g., HS256 instead of RS256) and potentially bypass signature verification.

## Source

Line 21 in `authMiddleware.js`:
```javascript
const claims = jwt.verify(token, publicKey);
```

The token is extracted from the Authorization header (line 13) and passed directly to `jwt.verify()` without constraining which signing algorithms are acceptable.

## Fix

Replace line 21:
```javascript
const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

Explicitly pass `{ algorithms: ['RS256'] }` to pin the signature verification to the intended algorithm family, preventing an attacker from submitting a token re-signed with HS256 or another algorithm.

## Explanation

The jsonwebtoken package's default behavior for `jwt.verify()` without an `algorithms` option infers the algorithm from the token's `alg` header field itself. This allows an attacker to craft a token claiming to use HS256 (HMAC with a symmetric key) in place of RS256 (RSA with a public key), potentially leading to signature bypass if the issuer's identity is not strictly enforced. Explicitly specifying `{ algorithms: ['RS256'] }` restricts verification to only RSA SHA-256 signed tokens, eliminating this attack vector. The key (a public key in this case) and the algorithm must agree; RS256 signature verification will reject an HS256-signed token regardless of the key format.

## Behaviour changes

- Tokens with `alg: RS256` in the header are verified as before.
- Tokens claiming any algorithm other than RS256 (HS256, none, etc.) are rejected with a JsonWebTokenError caught by the existing try-catch block, which returns 401 as intended.
- No change to successful authentication flow, session handling, or error reporting.
- Timing remains constant: credential comparison against the dummy hash pattern is not applicable here (that applies to password/credential lookups in Passport strategies); the fixed code still validates the token signature server-side before accepting the claims.
