## Verdict

exploitable (confidence: high)

`Math.random()` is used to generate a single-use invite code that is stored as the key granting access to join a workspace under a given email, and returned to the caller. This is a security-sensitive, unguessable-token use case: `Math.random()`'s output is a deterministic function of a non-cryptographic, unseeded-by-the-caller internal PRNG state and is not designed to resist prediction. An attacker who can observe a few generated codes (or brute-force the small keyspace produced by `slice(2, 10)`, at most 8 base-36 characters) can predict or guess valid invite codes and join workspaces they were not invited to.

## Source

`Math.random()` at line 18 of `MathRandomInviteCode.js`, inside the `POST /api/invites` handler. There is no earlier attacker-controlled input feeding the random value itself (`req.body.email` only supplies the association stored alongside the code) - the weak-PRNG call is itself the source of the tainted, predictable value, and the sink is its immediate use as the invite-code token: stored as the `pendingInvites` map key and returned in the JSON response (`res.json({ inviteCode })`), i.e. handed directly to whoever can invoke the endpoint.

Sink contract (`Math.random().toString(36).slice(2, 10)`):
- **Returns**: a string of up to 8 lowercase base-36 characters (`[0-9a-z]`); can be shorter if the random fraction's base-36 expansion has fewer digits.
- **Discards**: nothing beyond the unused leading `"0."` digits.
- **Arguments left implicit**: none - `Math.random()` takes no arguments.
- **Failure behaviour**: none; the call cannot throw.

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

  const inviteCode = crypto.randomBytes(16).toString('base64url');

  pendingInvites.set(inviteCode, { email, createdAt: Date.now() });

  res.json({ inviteCode });
});

module.exports = app;
```

## Explanation

The fix replaces `Math.random().toString(36).slice(2, 10)` with `crypto.randomBytes(16).toString('base64url')`, drawn from Node's `crypto` module (built-in, no new dependency). `crypto.randomBytes()` reads from the OS's cryptographically secure random source rather than a general-purpose PRNG, so its output cannot be predicted from prior outputs or reproduced by an attacker. 16 bytes (128 bits) meets the knowledge base's floor for session/bearer tokens - well above the effectively-32-bit-or-less keyspace of an 8-character base-36 string - and `base64url` encoding keeps the token URL-safe and usable as a Map key and JSON value exactly as before, without introducing characters that need extra escaping. No other logic in the handler (validation, storage, response shape) needed to change: the token is opaque to the rest of the application.

## Behaviour changes

- **Invite code format**: the value moves from up to 8 lowercase base-36 characters (`[0-9a-z]`) to a fixed 22-character base64url string (`[A-Za-z0-9_-]`), and length is now constant rather than variable. Reason: the base-36 format's keyspace is too small to resist guessing; base64url is the standard, URL-safe encoding for a `crypto.randomBytes()` token. Any downstream code, documentation, or client-side validation that assumes an 8-character lowercase-alphanumeric code will need to accept the new format.
- **Entropy**: increases from at most 8 base-36 digits (~41 bits, and often fewer since leading zero-digits are dropped) to a full 128 bits. This is the intended effect of the fix, not an incidental change.
- No other behaviour changes - the map key/value semantics, request validation, and response shape are unchanged.

## Verification

`node --check` was run against the fixed file (copied to a scratch location, not the case fixture) and reported no syntax errors. `crypto.randomBytes` and `.toString('base64url')` were additionally exercised directly with `node -e` to confirm they produce the expected 22-character URL-safe string. `crypto` is a Node.js built-in module already implicitly available in this Express codebase; no new package or manifest change is required.

## Assumptions

- The invite code's role (a single-use, emailed token whose possession grants workspace access) was inferred from the handler's comment and its use as a map key returned to the caller; treated as a security-sensitive bearer token per the knowledge base's "unguessable share URLs" and token guidance, not as a non-security identifier.
- `base64url` (rather than `hex`) was chosen for the encoded format since the code is likely to be embedded in a URL or entered by a user; no existing format constraint was found elsewhere in the file to contradict this.
