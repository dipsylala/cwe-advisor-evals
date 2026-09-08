## Verdict

**CONFIRMED: CWE-338** - `Math.random()` on line 18 is used to generate a single-use invite code, a security-sensitive bearer token that grants workspace access. `Math.random()` provides insufficient entropy (~53 bits) for a security token. The value is sent via email (observable), guessing it grants unauthorized access, and the single-use property enables brute-force attempts. This is a real and exploitable vulnerability.

## Source

**File**: MathRandomInviteCode.js, line 18

**Vulnerable code**:
```javascript
const inviteCode = Math.random().toString(36).slice(2, 10);
```

**Data flow**: 
1. `Math.random()` returns a predictable float
2. `.toString(36)` and `.slice(2, 10)` extract an 8-character string with low entropy
3. Stored in `pendingInvites` Map and returned to caller
4. Used as a bearer token to authorize workspace join requests (security-sensitive sink)

## Fix

Replace `Math.random()` with cryptographically secure `crypto.randomBytes()`:

### File: MathRandomInviteCode.js

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const pendingInvites = new Map();

// Generate a single-use invite code for the email address supplied by the
// caller and email it to them so they can join the workspace.
app.post('/api/invites', (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }

  // Generate cryptographically secure invite code with 128 bits of entropy
  const inviteCode = crypto.randomBytes(16).toString('hex');

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});

module.exports = app;
```

## Explanation

The fix replaces `Math.random()` with `crypto.randomBytes(16)`, which generates 16 cryptographically secure random bytes (128 bits of entropy). The `.toString('hex')` encoding produces a 32-character hexadecimal string.

This eliminates the weak PRNG vulnerability by providing unpredictable, non-reproducible random values suitable for security tokens. The 128-bit entropy is sufficient for a single-use invite code that grants access. Node.js's built-in `crypto` module is cryptographically secure and properly seeded by the OS, requiring no additional dependencies.

The guidance specifies `crypto.randomBytes(16)` for session and CSRF tokens; invite codes are equivalent security tokens and warrant the same treatment.

## Behaviour changes

1. **Entropy**: Increased from ~40-50 bits (Math.random base-36 slice) to 128 bits (crypto.randomBytes)
2. **Predictability**: `Math.random()` output is reproducible if the seed is known; `crypto.randomBytes()` is cryptographically unpredictable
3. **Format**: Invite code changes from an 8-character alphanumeric string (e.g., "a1b2c3d4") to a 32-character hexadecimal string (e.g., "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
   - Hexadecimal format is deterministic and widely supported
   - Longer string length provides no additional storage burden
4. **No functional regression**: The code still stores and retrieves the invite code from the Map exactly as before; only the generation mechanism changed
