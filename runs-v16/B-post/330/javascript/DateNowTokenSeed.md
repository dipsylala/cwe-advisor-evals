## Verdict

exploitable

## Source

Line 15 of DateNowTokenSeed.js: `Math.random().toString(36).substring(2)` is used to generate a password reset token, which is a security-critical value. The source is unpredictable in principle (uniform distribution across [0, 1)) but not cryptographically random - V8's xorshift128+ implementation is recoverable from a modest sequence of consecutive outputs, and there is no possibility of seeding or reseeding by the caller.

## Fix

**Vulnerable code:**
```javascript
const token = Math.random().toString(36).substring(2);
```

**Fixed code:**
```javascript
const crypto = require('node:crypto');

const token = crypto.randomBytes(16).toString('base64url');
```

(Add the `require('node:crypto')` import at the top of the file with the other requires.)

## Explanation

The fix replaces the general-purpose PRNG `Math.random()` with `crypto.randomBytes(16)`, which draws from the platform's cryptographic random source. A 16-byte (128-bit) token meets the OWASP ASVS floor for non-guessable values. The `'base64url'` encoding is URL-safe and is available in Node 15.7.0+ / 14.18.0+. The token is now unpredictable and resistant to enumeration attacks, closing the weakness while preserving the token's string representation and size.

## Behaviour changes

The returned token is now cryptographically random rather than pseudo-random, which is the intended security fix. The encoding changes from base-36 to base64url, which increases the entropy per character and improves the token's resistance to brute-force attacks. The token length may vary (base64url encoding of 16 bytes yields approximately 22-24 characters depending on padding), whereas the original `Math.random().toString(36).substring(2)` produced approximately 14-17 characters. This is not a breaking change because password reset tokens are treated as opaque values by the application - they are stored and compared without assumptions about their character set or length. The expiry time logic (`Date.now() + 3600000`) is unchanged.
