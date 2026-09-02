## Verdict

Exploitable. Confidence: high.

## Source

`Math.random()` at `MathRandomInviteCode.js:18`. `Math.random()` is a non-cryptographic PRNG (V8 uses xorshift128+); its output stream can be predicted from a handful of observed samples, and the generated value here is not incidental UI randomness - it is a single-use invite code that, once known, grants an attacker the ability to redeem the invite and join the workspace in place of the intended recipient. That makes it a security-sensitive token per the weak-PRNG guidance (comparable to a share URL or coupon code with access value), not a cosmetic use of randomness.

## Sink

The same statement, `const inviteCode = Math.random().toString(36).slice(2, 10);` (line 18). The result:

- **Returns**: an 8-character base-36 string (`slice(2, 10)` of the fractional digits), roughly 41 bits of nominal entropy before accounting for PRNG predictability.
- **Discards**: nothing beyond the digits sliced off.
- **Arguments left implicit**: none - `Math.random()` takes no arguments and `toString(36)` is a fixed radix.
- **Failure behaviour**: none; the call cannot throw.

Downstream, `inviteCode` is used as the key in `pendingInvites` (line 20) and returned directly to the caller in the JSON response (line 22) - so it is both the map key and the bearer value an invitee later presents to redeem the invite.

## Fix

Library recommendation: Node.js built-in `crypto` module (`crypto.randomBytes()`). No third-party dependency or version bump needed - `crypto` ships with Node.js.

Vulnerable code:

```javascript
const express = require('express');
const app = express();
...
app.post('/api/invites', (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }

  // SAST FINDING: CWE-338 reported here. Sink is the next statement.
  const inviteCode = Math.random().toString(36).slice(2, 10); // weak PRNG, predictable

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});
```

Fixed code:

```javascript
const crypto = require('crypto');
const express = require('express');
const app = express();
...
app.post('/api/invites', (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }

  const inviteCode = crypto.randomBytes(16).toString('base64url');

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});
```

## Explanation

`Math.random()` is replaced with `crypto.randomBytes(16)`, Node's CSPRNG, matching the 128-bit floor the JavaScript guidance specifies for tokens and session identifiers (invite codes fall in the same "unguessable bearer value" category). The bytes are encoded with `.toString('base64url')` rather than a manual base-36 conversion, producing a URL-safe ~22-character string suitable for use as both a JSON field and a map key, with no change to how the code is stored (`pendingInvites.set`) or returned (`res.json`). This closes the predictability weakness: an attacker who observes one or more issued codes can no longer infer the PRNG's internal state and predict codes issued to other invitees.

## Behaviour changes

- Invite code length and character set change from an 8-character base-36 string (`toString(36).slice(2, 10)`) to a ~22-character base64url string (`crypto.randomBytes(16).toString('base64url')`). Reason: the original length carried far less entropy than a security token requires; any client-side validation, storage column width, or display formatting that assumes an 8-character code will need to accommodate the longer value.
- A top-level `const crypto = require('crypto');` is added. Reason: required to call the CSPRNG; `crypto` is a Node.js built-in, so this adds no new dependency.
- Everything else - the map key/value shape, the response JSON shape (`{ inviteCode }`), the 400 validation path, and error behaviour - is unchanged.
