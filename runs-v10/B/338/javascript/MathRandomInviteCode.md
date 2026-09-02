## Verdict

Exploitable.

## Source

System-generated invite code without cryptographic randomness.

## Fix

**Vulnerable code (line 18):**
```javascript
const inviteCode = Math.random().toString(36).slice(2, 10);
```

**Fixed code:**
```javascript
const crypto = require('crypto');
const inviteCode = crypto.randomBytes(16).toString('hex');
```

## Explanation

The original code uses `Math.random()`, a cryptographically weak PRNG unsuitable for generating security-sensitive values like invite codes that control access to resources. `Math.random()` is predictable and can be reproduced by attackers. The fix replaces it with `crypto.randomBytes(16)`, which generates 128 bits (16 bytes) of cryptographically secure randomness and converts it to hexadecimal—providing sufficient entropy for a bearer token used in access control, while remaining unpredictable and unreproducible across sessions.

## Behaviour changes

The `crypto` module must be imported at the top of the file with `const crypto = require('crypto');` (or `const { randomBytes } = require('crypto');` if preferred). The generated `inviteCode` format changes from an 8-character base-36 string to a 32-character hexadecimal string, so any validation, logging, or documentation expecting the old format must be updated accordingly. The invite code is now cryptographically unpredictable and resistant to brute-force attacks.
