## Verdict
CWE-338 confirmed: `Math.random()` on line 18 is a cryptographically weak PRNG unsuitable for security-sensitive operations like invite codes. Remediated by substituting Node.js's `crypto.randomBytes()`.

## Source
`Math.random()` produces predictable output via a simple linear congruential generator. Attackers can predict invite codes and bypass access controls.

## Fix

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

  // SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
  const inviteCode = crypto.randomBytes(8).toString('hex');

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});

module.exports = app;
```

## Explanation
Replaced `Math.random().toString(36).slice(2, 10)` with `crypto.randomBytes(8).toString('hex')`. This generates 8 random bytes (64 bits) as a 16-character hexadecimal string, providing cryptographic security suitable for single-use invite codes. The `crypto` module is Node.js's standard library for cryptographic operations and implements CSPRNG-grade randomness.
