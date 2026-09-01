## Verdict

Real issue confirmed. Line 18 uses `Math.random()` to generate a single-use invite code for workspace access, which is cryptographically weak and predictable.

## Source

Line 18:
```javascript
const inviteCode = Math.random().toString(36).slice(2, 10);
```

`Math.random()` produces predictable values from a weak PRNG unsuitable for security-sensitive tokens. Attackers can predict or brute-force valid invite codes.

## Fix

Replace with `crypto.randomBytes()`:

```javascript
const crypto = require('crypto');
const inviteCode = crypto.randomBytes(6).toString('hex');
```

Alternatively, use `crypto.randomUUID()`:

```javascript
const crypto = require('crypto');
const inviteCode = crypto.randomUUID();
```

Both approaches use Node.js's cryptographically secure `crypto` module (available in all maintained Node.js versions).

## Explanation

`Math.random()` is a weak PRNG designed for simulation and games, not security. Its output is:
- Predictable given the initial seed
- Low entropy (53 bits of state in most engines)
- Unsuitable for authentication tokens or access grants

Invite codes grant workspace membership. A weak PRNG allows attackers to enumerate or predict valid codes without being sent them, bypassing the single-use intent.

Node.js's `crypto.randomBytes()` uses the operating system's cryptographically secure random source (CryptGenRandom on Windows, `/dev/urandom` on Unix), providing sufficient entropy for authentication tokens. `randomBytes(6)` gives 48 bits of entropy, encoded as 12 hex characters—more entropy than the original 8-character base-36 string and immune to prediction.
