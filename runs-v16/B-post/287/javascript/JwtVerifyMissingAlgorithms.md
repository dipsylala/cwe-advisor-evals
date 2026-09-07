## Verdict

CONFIRMED: CWE-287 (Improper Authentication) - JWT algorithm confusion via missing algorithm pinning.

## Source

File: `evals/cases/287/javascript/JwtVerifyMissingAlgorithms/authMiddleware.js`
Line: 21

Data flow:
- **Source**: `token` from `req.headers['authorization']` (attacker-controlled via HTTP request)
- **Sink**: `jwt.verify(token, publicKey)` on line 21
- **Attack vector**: An attacker crafts a token with `alg: HS256` instead of `RS256`, signs it using the public key as the HMAC secret, and `jwt.verify()` accepts it because no `algorithms` option constrains the accepted algorithms.

## Fix

**Vulnerable code (line 21):**
```javascript
const claims = jwt.verify(token, publicKey);
```

**Fixed code:**
```javascript
const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

## Explanation

The vulnerability occurs because `jwt.verify()` is called without the `algorithms` option, allowing an attacker to perform algorithm confusion. By default, `jsonwebtoken` accepts the algorithm claimed in the token's header without verification against a server-side allowlist.

An RS256-protected application loads a public key for signature verification. An attacker can create a token with `alg: HS256` and sign it using the public key as an HMAC secret (publicly known because it is a public key). Without algorithm pinning, `jwt.verify()` reads the `alg` header, sees HS256, and verifies the HMAC using the public key, treating the forged token as legitimate.

The fix explicitly passes `{ algorithms: ['RS256'] }` to `jwt.verify()`, forcing the library to reject any token that does not claim RS256. This prevents algorithm confusion by establishing a server-side allowlist that tokens cannot override.

## Behaviour changes

- **Before**: Any token with a valid signature under any supported algorithm is accepted.
- **After**: Only tokens signed with RS256 are accepted; tokens signed with HS256, HS512, or any other algorithm are rejected with `JsonWebTokenError`.
- **No semantic changes**: The function still returns the decoded claims object on success and throws on error. The caller's exception handling (line 24-26) remains valid.
