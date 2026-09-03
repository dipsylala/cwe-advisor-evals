## Verdict

Exploitable. `Math.random().toString(36).substring(2)` at line 15 generates a password reset token with insufficient entropy. `Math.random()` implements xorshift128+ with a recoverable internal state from a modest run of outputs, and ECMA-262 makes no cryptographic guarantees. An attacker who collects a sequence of reset tokens can recover the internal state and predict future tokens, compromising all password reset flows until rotation occurs.

## Source

`Math.random()` at line 15, used to generate a password reset token in the `/forgot-password` endpoint.

## Fix

**Vulnerable code:**
```javascript
const token = Math.random().toString(36).substring(2);
```

**Fixed code:**
```javascript
const crypto = require('crypto');

// At line 1 or top of router definitions, add:
const crypto = require('crypto');

// At line 15, replace with:
const token = crypto.randomBytes(16).toString('base64url');
```

The full corrected file:
```javascript
const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const resetTokens = new Map();

// Generate a password reset token for the account tied to the submitted email.
router.post('/forgot-password', (req, res) => {
  const email = req.body.email;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'email is required' });
  }

  // FIXED: Use crypto.randomBytes for cryptographically secure token generation
  const token = crypto.randomBytes(16).toString('base64url');

  resetTokens.set(token, { email, expires: Date.now() + 3600000 });

  sendResetEmail(email, token);

  res.json({ message: 'If that email exists, a reset link was sent.' });
});

function sendResetEmail(email, token) {
  console.log(`Reset link for ${email}: https://example.com/reset?token=${token}`);
}

module.exports = router;
```

## Explanation

The original code used `Math.random().toString(36).substring(2)` to generate a password reset token, but `Math.random()` is not cryptographically secure. It uses xorshift128+, which has a recoverable internal state; knowing several sequential outputs allows an attacker to predict all future values. This is catastrophic for password reset tokens, which must be unpredictable and unique. The fix replaces it with `crypto.randomBytes(16)`, which draws from the operating system's cryptographic entropy source, generating 128 bits of entropy (the OWASP ASVS floor for non-guessable values). The `.toString('base64url')` encoding produces a URL-safe string suitable for use in reset links without additional escaping. This fix requires Node.js 14.18.0 or 15.7.0+ for full `base64url` support.

## Behaviour changes

- Added `const crypto = require('crypto');` import at the top of the module
- `crypto.randomBytes(16).toString('base64url')` produces 24 characters (16 bytes × 4/3 base64 expansion, no padding in URL variant), whereas the original `Math.random().toString(36).substring(2)` typically produced 12–14 characters. The longer token provides stronger collision resistance
- The entropy per token increased from ~52 bits (Math.random's effective entropy) to 128 bits (cryptographic random source)
- Token format changed from alphanumeric base36 to URL-safe base64url characters
- No change to the token storage mechanism, expiration, or email delivery logic—only the source of randomness changed
