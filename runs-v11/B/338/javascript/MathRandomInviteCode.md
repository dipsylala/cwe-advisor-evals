## Verdict

Finding is **CONFIRMED**. Line 18 uses `Math.random()` to generate single-use invite codes, a security-sensitive operation where attackers could predict tokens and forge invites to join workspaces.

## Source

```javascript
const inviteCode = Math.random().toString(36).slice(2, 10);
```

`Math.random()` is a general-purpose pseudo-random number generator with predictable output, making it unsuitable for security operations like token generation.

## Fix

```javascript
const crypto = require('crypto');

const inviteCode = crypto.randomBytes(12).toString('base64url');
```

**Changes:**
1. Import `crypto` module at the top of the file: `const crypto = require('crypto');`
2. Replace `Math.random().toString(36).slice(2, 10)` with `crypto.randomBytes(12).toString('base64url')`

The fix generates 96 bits (12 bytes) of cryptographically secure randomness and encodes it as URL-safe base64, suitable for invite codes transmitted in URLs or stored directly.

## Explanation

`Math.random()` in JavaScript produces low-entropy output derived from a standard PRNG that can be recreated or predicted, especially when the seed or timing is observable. Invite codes grant access to a workspace and must be impossible to guess or brute-force.

`crypto.randomBytes(12)` generates 96 bits of OS-sourced entropy from `/dev/urandom` on Unix-like systems or `CryptGenRandom` on Windows, meeting the threshold for security-sensitive tokens. The output is converted to `base64url` encoding (URL-safe without padding), which is compact and safe for transmission in URLs, headers, or stored as-is in databases.

The invite code is no longer reproducible, guessable, or predictable across sessions.

## Behaviour changes

- **Runtime behavior:** Invite code format changes from decimal-based alphanumeric to base64url encoding. The new codes are longer but remain string type. Existing pending invites will still work (not regenerated).
- **Security behavior:** Invite codes are now cryptographically unpredictable. An attacker with access to one code cannot derive or predict others, and brute-force guessing becomes infeasible (2^96 possible values).
- **Storage:** The `pendingInvites` Map stores the new format; no migration needed if only live codes matter. Persisted codes use the old format; consider a small migration window or accept old formats alongside new.
- **Length:** The new code is approximately 16 characters (12 bytes in base64url), longer than the old 8-character format. Callers expecting the shorter format will need to be notified of the change.
