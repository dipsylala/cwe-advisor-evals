## Verdict

- **cwe_id**: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG))
- **location**: `MathRandomInviteCode.js:18`
- **verdict**: exploitable
- **confidence**: high

## Source

- **Sink**: `Math.random().toString(36).slice(2, 10)` at line 18, assigned to `inviteCode`.
- **Data flow**: `inviteCode` is generated purely from `Math.random()` (no external input feeds the value itself). It is immediately used as the key in `pendingInvites` (line 20) - a single-use, workspace-join token bound to the submitted `email` - and returned to the caller in the JSON response (line 22), which the caller is expected to relay to the invited email address.
- **Why it's security-sensitive**: the code is a bearer credential - anyone who has or guesses it can be associated with `pendingInvites.get(inviteCode)` and complete the workspace join for that entry. `Math.random()` in V8 is a non-cryptographic xorshift128+ PRNG; its internal state can be recovered from a handful of observed outputs, and the output here is further truncated to 8 base-36 characters (at most ~41 bits, well under any usable floor), so codes are both statistically guessable and predictable once any output is observed. This satisfies all three "moves toward finding" conditions from the CWE-338 guidance: the value is observable by someone not entitled to it (it's emailed out and handled over HTTP), guessing it grants access rather than just revealing information, and a pending invite is long-lived enough to allow repeated guesses.

## Fix

No third-party library is required - Node's built-in `crypto` module supplies the fix.

Vulnerable code:
```javascript
// SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
const inviteCode = Math.random().toString(36).slice(2, 10);
```

Fixed code:
```javascript
const crypto = require('crypto');
// ...
// Cryptographically secure invite code: 128 bits of entropy, hex-encoded.
const inviteCode = crypto.randomBytes(16).toString('hex');
```

(`const crypto = require('crypto');` goes with the other top-of-file `require`s, e.g. alongside the `express` import.)

## Explanation

`Math.random()` is a general-purpose, non-cryptographic PRNG and must not be used to produce a value that grants access, per the CWE-338 JavaScript guidance's taint sink list and remediation steps. The fix replaces it with `crypto.randomBytes(16).toString('hex')`, which draws from the OS CSPRNG and yields 128 bits of entropy (32 hex characters) - matching the guidance's floor for session/bearer tokens ("`crypto.randomBytes(16)` (128 bits) for session tokens and CSRF tokens"), which an invite code that grants workspace access is functionally equivalent to. `crypto.randomBytes` is synchronous here and does not change the function's control flow, error behavior, or the fact that the result is a `string` assigned to `inviteCode`, so it satisfies the sink's existing contract (return type consumed the same way, no arguments to preserve, no thrown-error path introduced beyond the pre-existing, already-unhandled possibility of an OS entropy failure).

## Behaviour changes

- **Invite code format/length changed**: from a variable-length (up to 8-character) base-36 string (`[0-9a-z]`) to a fixed 32-character hex string (`[0-9a-f]`). Reason: required to reach the 128-bit entropy floor the guidance specifies for a bearer token of this kind - the original 8-char base-36 code carried at most ~41 bits even before accounting for `Math.random()`'s predictability. No code in this file parses, validates, or asserts a length/charset on `inviteCode`, so this is not expected to break the shown logic, but any downstream consumer (email template, client-side validation, storage schema) that assumes the old 8-character shape should be checked and updated.
- No other differences: arguments, return handling, error handling, and the `pendingInvites` map/`res.json` usage are otherwise unchanged from the original.
