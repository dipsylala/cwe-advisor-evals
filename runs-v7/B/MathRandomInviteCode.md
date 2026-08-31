## Verdict

Exploitable. `Math.random()` is cryptographically weak and produces predictable values. The invite code is a security-sensitive single-use token that authenticates users joining the workspace; attackers can predict and forge invite codes to gain unauthorized access.

## Source

`Math.random()` at line 18 generates random values for security-sensitive token generation.

## Fix

**Vulnerable code:**
```javascript
  const inviteCode = Math.random().toString(36).slice(2, 10);
```

**Fixed code:**
```javascript
const crypto = require('crypto');

// ... in the route handler ...
  const inviteCode = crypto.randomBytes(16).toString('hex');
```

## Explanation

Replace `Math.random()` with `crypto.randomBytes(16)`, which provides 128 bits of cryptographically secure randomness, sufficient for a single-use authentication token. The `.toString('hex')` conversion produces a 32-character hexadecimal string that serves as the invite code. This eliminates the predictability weakness while maintaining the functional contract: a unique, non-guessable identifier stored as a map key and returned to the client for later validation.

## Behaviour changes

- `crypto` module is required at the top of the file (new import statement needed)
- Invite codes are now 32 hexadecimal characters instead of 8 alphanumeric characters
  - Reason: `crypto.randomBytes(16)` returns 16 bytes; `.toString('hex')` encodes each byte as 2 hex digits
  - The longer format carries 128 bits of entropy instead of ~42 bits, meeting the guidance requirement for token material
  - No functional impact: the code is used only as a unique identifier in the `pendingInvites` map key lookup; the length change does not affect validity checking or workflow logic
