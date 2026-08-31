## Verdict
Confirmed. `Math.random()` is cryptographically weak and unsuitable for generating security-sensitive tokens.

## Source
Line 18 uses `Math.random().toString(36).slice(2, 10)` to generate an invite code. This produces a predictable, non-cryptographic random value that can be brute-forced or guessed by an attacker, compromising the single-use invite mechanism.

## Fix
Replace the weak PRNG with Node.js's cryptographic random generator:

```javascript
const crypto = require('crypto');

app.post('/api/invites', (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }

  const inviteCode = crypto.randomBytes(8).toString('hex');

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});
```

## Explanation
`Math.random()` is a weak PRNG designed for casual randomization, not cryptographic use. Its output is predictable and has a small internal state that attackers can brute-force or guess. Invite codes are security-sensitive tokens that protect account access, requiring cryptographic strength.

`crypto.randomBytes(8)` generates 8 bytes (64 bits) of cryptographically secure random data from the OS entropy pool, then encodes to hex for readability. This provides sufficient entropy to make brute-force guessing infeasible.
