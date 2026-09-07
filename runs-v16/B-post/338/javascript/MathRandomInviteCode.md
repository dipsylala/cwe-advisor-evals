## Verdict

**REMEDIATED** — The application generates invite codes using `Math.random()`, a cryptographically weak PRNG unsuitable for security-sensitive tokens. An attacker can predict future invite codes to forge access to workspaces. The fix replaces `Math.random()` with `crypto.randomBytes()`, raising entropy from ~26 bits to 128 bits and making the code unpredictable.

## Source

**File**: `MathRandomInviteCode.js`
**Line**: 18
**Code**:
```javascript
const inviteCode = Math.random().toString(36).slice(2, 10);
```

**Context**: The invite code is generated once per email and stored as the sole key in a map that grants workspace access to anyone who presents it. The code is the security boundary: predicting it bypasses email verification.

**Sink**: `Math.random()` — a non-cryptographic PRNG unsuitable for tokens, keys, or nonces.

## Fix

**Add `crypto` module import** at the top of the file (if not already present):
```javascript
const crypto = require('crypto');
```

**Replace line 18**:
```javascript
const inviteCode = crypto.randomBytes(16).toString('hex');
```

**Rationale**: `crypto.randomBytes(16)` generates 128 bits of cryptographically secure randomness and converts it to a 32-character hex string. This is the Node.js standard for security tokens and invite codes — sufficient entropy, unpredictable, and verified by the crypto module itself (seeded by the OS).

## Explanation

The original code combines three weaknesses: `Math.random()` is not cryptographically secure (predictable), `.toString(36)` reduces entropy, and `.slice(2, 10)` produces only 8 characters (~26 bits effective entropy). An attacker who observes a single invite code can predict the next codes and forge arbitrary invites.

The fix replaces `Math.random()` with `crypto.randomBytes(16)`, which:
- Generates 128 bits of entropy from the operating system's secure random pool
- Cannot be predicted given prior values
- Converts to hex for safe storage and transmission (32 characters)
- Meets the JavaScript guidance minimum of 16 bytes (128 bits) for tokens and session IDs

The invite code is now computationally infeasible to guess: attempting 2^128 codes is prohibitive even in a massively parallel attack.

## Behaviour changes

- **Invite code format**: Changes from an 8-character alphanumeric base-36 string (e.g., `"a1b2c3d4"`) to a 32-character hexadecimal string (e.g., `"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"`). Any client-side code that assumes the 8-character length will need updating.
- **Entropy**: Increases from ~26 bits to 128 bits, making brute-force prediction infeasible.
- **Reproducibility**: Lost — the same call no longer generates the same code (intentional; predictability was the vulnerability).
- **Backwards compatibility**: Existing invite codes in the `pendingInvites` map will remain valid, but new invites use the stronger format. A migration is optional unless the application encodes assumptions about format into other logic.
