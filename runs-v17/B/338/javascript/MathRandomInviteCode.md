## Verdict

Exploitable.

## Source

`Math.random()` at line 18 of MathRandomInviteCode.js

## Sink

The generated invite code is returned to clients and stored as a bearer token for workspace access. Predictable values allow attackers to forge valid invite codes and gain unauthorized access.

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

  const inviteCode = crypto.randomBytes(16).toString('hex');

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});

module.exports = app;
```

## Explanation

The fix replaces `Math.random()` with `crypto.randomBytes(16).toString('hex')`, which generates 128 bits of cryptographically secure randomness and encodes it as a 32-character hexadecimal string. This eliminates the predictability of the invite code while maintaining the same API contract and data structure. The invitation remains a string key suitable for storage in the Map and transmission to the client; the only change is that codes are now cryptographically strong instead of easily guessable.

## Behaviour changes

The invite code format changes from an 8-character base36 string to a 32-character hexadecimal string. This is a necessary side effect of using cryptographically secure randomness; it does not break functionality because the code is still a string key that maps to invitation data. Clients receiving the API response will see longer codes, which is an acceptable trade-off for security-sensitive tokens.
