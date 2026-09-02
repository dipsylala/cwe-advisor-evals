## Verdict

exploitable, confidence: high

Line 15 mints a password-reset token with `Math.random()`. This is a security-relevant secret (possession of it lets an attacker take over the account tied to the email), and V8's `Math.random()` is xorshift128+ - its internal state is recoverable from a modest run of consecutive outputs and offers no cryptographic guarantee of unpredictability. There is no validating or constraining step between generation and use, so the weak value reaches the sink unmodified.

## Source

- **Source**: `Math.random()` (line 15) - a non-cryptographic PRNG, not an attacker-controlled input; the weakness is the generator itself, not tainted data reaching it.
- **Sink**: `resetTokens.set(token, { email, expires: ... })` (line 17) and the token embedded in the emailed reset URL via `sendResetEmail(email, token)` (line 19, resolved at line 25: `https://example.com/reset?token=${token}`). The token is the sole credential validated on the reset flow's completion step (not shown in this file, but implied by `resetTokens`).
- Encoding step: `.toString(36).substring(2)` truncates the float's base-36 representation and strips the leading `"0."` - this changes the string's shape but adds no entropy, so it does not affect the finding.

## Fix

Vulnerable code (`DateNowTokenSeed.js`, line 15):

```javascript
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
const token = Math.random().toString(36).substring(2);
```

Fixed code:

```javascript
const crypto = require('crypto'); // add to the top-level requires

// ...

const token = crypto.randomBytes(16).toString('base64url');
```

No third-party library is needed - `node:crypto` is a Node.js built-in. `crypto.randomBytes(16)` draws 16 bytes (128 bits) from the platform CSPRNG, meeting the OWASP ASVS floor for a non-guessable value; `.toString('base64url')` is a `Buffer` encoding and works directly on the returned `Buffer` (unlike `crypto.getRandomValues`, which would need explicit `Uint8Array` handling). The `'base64url'` encoding requires Node 15.7.0 / 14.18.0 or later - on an older Node runtime, use `.toString('hex')` instead (32 hex characters still carries the same 128 bits).

## Explanation

The fix replaces the generator, not the seed or the encoding, per the loaded guidance: `Math.random()` is unsuitable for security tokens under any post-processing, because whatever is derived from it stays fully determined by its predictable output. `crypto.randomBytes` is Node's cryptographic RNG and is the pattern the language-specific guidance names for exactly this token-generation case. The rest of the flow - storing the token as the map key, embedding it in the reset URL, and the 1-hour expiry - is unchanged, since none of that is the source of the weakness.

## Behaviour changes

- **Token value and length**: the token changes from a variable-length (roughly 10-11 character) base-36 string to a fixed-length, unpredictable base64url string (22 characters for 16 bytes, no padding). Any code elsewhere that assumes the old token's length or character set (e.g. a regex validating the token format before lookup) needs to accommodate the new shape - none is present in this file.
- **New import**: `require('crypto')` is added. This is a Node built-in with no new dependency and no version to track via SCA.
- **Token rotation**: not applicable here - `resetTokens` is an in-memory `Map`, so no previously issued tokens persist across a deploy of this fix; any tokens already issued from the unfixed code remain valid only until the process restarts or their 1-hour expiry passes, whichever comes first.
- Everything else in the sink's contract is preserved: `resetTokens.set` still receives the same `{ email, expires }` shape, `sendResetEmail` is still called with the same arguments, and the HTTP response is unchanged.
