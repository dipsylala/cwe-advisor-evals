## Verdict

exploitable

- cwe_id: CWE-330 (Use of Insufficiently Random Values)
- location: `DateNowTokenSeed.js`, line 15 (`const token = Math.random().toString(36).substring(2);`)
- confidence: high

## Source

`Math.random()` is the source of the weakness itself: ECMA-262 defines it only as an "implementation-defined algorithm or strategy" with approximate uniform distribution and no guarantee of unpredictability. V8 implements it with xorshift128+, whose internal state can be recovered from a modest run of consecutive outputs, and the generator cannot be reseeded or hardened by the caller.

Data flow: `req.body.email` (attacker-controlled request body) selects the account, but the vulnerable value is generated independently of any input - `Math.random()` is called directly at line 15, `.toString(36).substring(2)` reshapes the output into a short alphanumeric string without adding entropy, the result is stored as the key of `resetTokens` (the sole authentication credential for completing a password reset), and the same value is emailed to the user inside the reset URL (`sendResetEmail`, line 19/25). Anyone who can predict or brute-force the generator's output can mint a valid reset token for an arbitrary email address and take over that account - this is the sink the fix must close.

## Fix

### File: DateNowTokenSeed.js

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

The fix replaces the general-purpose PRNG with Node's cryptographic generator: `crypto.randomBytes(16)` draws 16 bytes (128 bits) from the platform CSPRNG, meeting the OWASP ASVS floor for a non-guessable token, and `.toString('base64url')` encodes those bytes into a URL-safe string suitable for direct use in the reset link's query string. This is the platform token API the JavaScript guidance names for this exact case (server-side secrets/tokens), rather than a re-seeded or re-hashed version of `Math.random()` - hashing or reshaping a weak value does not add entropy, only the generator itself does. `require('crypto')` is Node's built-in `crypto` module (no new dependency), and `randomBytes`/`Buffer.prototype.toString('base64url')` are documented Node APIs; `'base64url'` as a `Buffer` encoding requires Node >= 15.7.0/14.18.0 (confirmed available on the Node v24.3.0 used to verify this fix). The rest of the handler - validation, the `resetTokens` map, the expiry calculation, and the email dispatch - is unchanged, since the weakness and its sink were confined to how the token value itself was generated.

## Behaviour changes

- Token character set changes from base-36 (digits and lowercase letters, from `Math.random().toString(36)`) to base64url (`A-Z a-z 0-9 - _`). Both are URL-safe and require no additional encoding in the reset link's query string, so the emailed link's format still parses the same way (`?token=<value>`).
- Token length changes from a variable ~11-13 characters (whatever `Math.random().toString(36).substring(2)` happens to produce) to a fixed 22 characters (base64url encoding of 16 bytes). This is required to carry the 128 bits of entropy the guidance requires and is not narrowed or truncated afterward.
- Every `require`, function, and API the fixed code adds (`require('crypto')`, `crypto.randomBytes`, `Buffer.prototype.toString('base64url')`) is a built-in Node.js API already named by the loaded JavaScript guidance, not a new third-party dependency - no library/version recommendation applies here.
- No change to `resetTokens` semantics, expiry logic, response shape, or error handling.
- Not addressed by this fix: `resetTokens` is an in-memory `Map`, so any tokens already issued by the vulnerable generator do not persist across a process restart and there is nothing to explicitly rotate in this code path; if this map is backed by persistent storage in the real deployment, previously issued tokens should be invalidated separately, since pointing new generation at `crypto.randomBytes` does not revoke tokens already handed out.

## Verification

`node --check` was run against the fixed file on Node v24.3.0 and returned no errors (syntax valid). `crypto.randomBytes(16).toString('base64url')` was also executed directly on the same Node version to confirm the API and encoding are available and produce a URL-safe string (e.g. `bCzPQs-XRJNr99_d9ZmFrg`). No test suite was available for this fixture to run.

**Assumptions**: Node runtime version for the real deployment target is unstated in the case; `'base64url'` Buffer encoding requires Node >= 15.7.0/14.18.0, verified only against the Node v24.3.0 available in this environment. Assumed `resetTokens` has no persistent/external backing beyond the in-memory `Map` shown, so no separate token-rotation step was added; if that assumption is wrong, previously issued tokens still need explicit invalidation.
