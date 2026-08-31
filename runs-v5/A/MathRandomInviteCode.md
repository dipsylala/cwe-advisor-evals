## Verdict
Confirmed. `Math.random()` is used to construct a security-sensitive, single-use invite code, which is a cryptographically weak PRNG (CWE-338). Its output is not unpredictable enough to resist guessing/brute-force by an attacker who wants to redeem someone else's invite.

## Source
- File: `MathRandomInviteCode.js`
- Sink: line 18, `Math.random().toString(36).slice(2, 10)` — the generated value (`inviteCode`) is stored as the sole credential proving the right to join a workspace on behalf of the target `email`, and is later presumably emailed and redeemed with no other secret involved.

## Fix
Replace the `Math.random()`-based token with one drawn from Node's CSPRNG (`crypto` module), keeping the same map-key usage:

```js
const crypto = require('crypto');
const express = require('express');
const app = express();

app.use(express.json());

const pendingInvites = new Map();

app.post('/api/invites', (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }

  // Cryptographically secure invite code: 128 bits of entropy, URL-safe.
  const inviteCode = crypto.randomBytes(16).toString('base64url');

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});

module.exports = app;
```

## Explanation
`Math.random()` is backed by a non-cryptographic PRNG (V8 uses xorshift128+). Its internal state can be recovered from a handful of observed outputs, and even without that, its 2^53-ish output space is small enough, and unseeded per-process rather than per-value, that invite codes derived from it are guessable far faster than brute force should allow. Since the invite code is the only thing standing between an attacker and joining someone else's workspace, it must come from a CSPRNG.

`crypto.randomBytes(16)` pulls 128 bits directly from the platform's cryptographically secure RNG, well above what's brute-forceable. Encoding with `.toString('base64url')` keeps the code compact and safe to embed in a URL or query string (no `+`, `/`, or `=` characters), unlike the original `.toString(36)` output, and produces a fixed-length code rather than one that depends on the numeric value of the random draw. This uses only Node's built-in `crypto` module, so no new dependency is introduced. Everything else about the flow — the `Map` keyed by `inviteCode`, the response shape — is unchanged.
