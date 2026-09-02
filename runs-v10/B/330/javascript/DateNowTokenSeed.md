## Verdict

The finding is valid. Line 15 uses `Math.random().toString(36).substring(2)` to generate a password reset token. Math.random() is unsuitable for any security-sensitive value; ECMA-262 provides no unpredictability guarantee, and V8 implements it as xorshift128+, whose state can be recovered from consecutive outputs. Encoding the output does not add entropy.

## Source

`Math.random()` at line 15 in DateNowTokenSeed.js, transformed through `.toString(36).substring(2)` and used as a password reset token (line 17: `resetTokens.set(token, ...)`).

## Fix

Replace line 15 with:

```javascript
const crypto = require('crypto');
const token = crypto.randomBytes(16).toString('base64url');
```

Or, if crypto is already imported at the top of the file, use only:

```javascript
const token = crypto.randomBytes(16).toString('base64url');
```

The `randomBytes(16)` call generates 16 bytes (128 bits) of cryptographic randomness, meeting OWASP ASVS requirements for tokens. The `base64url` encoding produces a URL-safe string suitable for sending in email links.

## Explanation

`Math.random()` is not suitable for cryptographic purposes. Its internal state can be recovered from a modest run of consecutive outputs, making tokens predictable once an attacker observes a few resets. Encoding or transforming the output (as `.toString(36).substring(2)` does) does not add entropy—it merely changes how the predictable value looks.

The fix switches to `crypto.randomBytes()`, which draws from the system's cryptographic random source (the OS entropy pool on Unix/Linux, `CryptGenRandom` on Windows). This ensures each token is unpredictable. The 16-byte size (128 bits) meets the ASVS 128-bit floor for non-guessable identifiers. Base64url encoding is safe for inclusion in URLs and email links.

## Behaviour changes

- Password reset tokens are now cryptographically random and unguessable.
- Token length increases from variable (~10-12 characters) to fixed 24 characters (16 bytes in base64url encoding).
- Character set changes from base36 alphanumerics to base64url characters (A-Z, a-z, 0-9, `-`, `_`).
- Any existing tokens issued before the fix remain valid until expiration (as designed).
