## Verdict

exploitable

## Source

`token` extracted from the `Authorization` header (line 13), passed to `jwt.verify()` without algorithm validation (line 21).

## Fix

**Vulnerable code:**
```javascript
const claims = jwt.verify(token, publicKey);
```

**Fixed code:**
```javascript
const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

## Explanation

The vulnerability occurs because `jwt.verify()` is called without specifying the `algorithms` option, allowing the token's `alg` header to dictate which algorithm is used for verification. An attacker can exploit this to perform an algorithm-confusion attack by:
- Submitting a token signed with `alg: none` (accepted as unsigned if no algorithms are pinned)
- Submitting a token re-signed with a symmetric algorithm (e.g., HS256) if the attacker knows the public key, which can be retrieved from public endpoints or certificates

The fix pins the accepted algorithms to an explicit allowlist `['RS256']`, matching the documented RS256-signed JWT that this middleware expects. This prevents the attacker from switching to an alternate algorithm and closes the algorithm-confusion vector entirely. The fix is applied at the point of verification (line 21) and matches the safe pattern prescribed by `jsonwebtoken` 9.0.2+.

## Behaviour changes

None. Adding the explicit `algorithms` option does not change what `jwt.verify()` returns, does not alter error handling, and does not affect how the returned claims are used. The only behavioral difference is rejection of tokens with mismatched or absent algorithms, which is the intended security hardening.
