## Verdict

exploitable

## Source

`Math.random()` at line 18 in MathRandomInviteCode.js, used to generate a single-use invite code for workspace access.

## Fix

**Vulnerable code:**
```javascript
const inviteCode = Math.random().toString(36).slice(2, 10);
```

**Fixed code:**
```javascript
const crypto = require('crypto');
const inviteCode = crypto.randomBytes(16).toString('hex');
```

## Explanation

The original code uses `Math.random()`, a general-purpose PRNG not suitable for security-sensitive operations. The generated 8-character invite code can be predicted or brute-forced by an attacker, allowing unauthorized access to the workspace. The fix replaces it with `crypto.randomBytes(16)`, which generates 128 bits (16 bytes) of cryptographically secure random data, converted to a 32-character hex string. This provides sufficient entropy to prevent guessing or prediction attacks. The fixed code maintains the same return type (string) and integration with the rest of the application.

## Behaviour changes

- **Entropy increase**: From ~26 bits to 128 bits (16-character base36 to 32-character hex)
- **Predictability**: Changed from reproducible with seed knowledge to cryptographically unpredictable
- **String length**: Invite codes are now 32 characters instead of 8, requiring any downstream code that accepts these codes to handle the longer length
- **Requires import**: The `crypto` module must be imported at the top of the file
