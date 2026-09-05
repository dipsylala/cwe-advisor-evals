## Verdict

Confirmed CWE-338: `Math.random()` is cryptographically weak and unsuitable for generating security-sensitive invite codes. Attackers can predict these values with trivial computational effort.

## Source

**File:** MathRandomInviteCode.js  
**Line:** 18  
**Vulnerable code:**
```javascript
const inviteCode = Math.random().toString(36).slice(2, 10);
```

**Why it's unsafe:** `Math.random()` is a general-purpose PRNG designed for non-security use (animations, UI randomization, games). It has at most 53 bits of entropy and is predictable. Invite codes grant access to join a workspace—they are security-sensitive bearer tokens and require cryptographic randomness.

## Fix

Replace `Math.random()` with Node.js's `crypto.randomBytes()`:

```javascript
const crypto = require('crypto');

// At the top of the file, add:
const crypto = require('crypto');

// Replace line 18:
const inviteCode = crypto.randomBytes(12).toString('hex');
```

**Why this works:** `crypto.randomBytes()` draws from the operating system's cryptographically secure random source (e.g. `/dev/urandom` on Unix, `CryptGenRandom` on Windows). The 12 bytes (96 bits) provides sufficient entropy for a single-use, short-lived invite token. Converting to hex produces a 24-character string suitable for email distribution.

## Explanation

Invite codes must be unpredictable because:
- They are sent to users via email (observable but only by the intended recipient)
- Guessing a valid code grants workspace access (high impact)
- They are short-lived but remain valid across multiple accesses during a session

The current code generates invite codes from `Math.random()`, which is seeded with limited entropy and follows a predictable Mersenne Twister sequence. An attacker knowing the system time or observing a few valid codes can deduce the PRNG state and generate or predict future codes.

`crypto.randomBytes()` sources randomness directly from the OS kernel's entropy pool, which is cryptographically seeded and non-deterministic. No attacker can predict or deduce the sequence without breaking the system's cryptographic primitives.

## Behaviour changes

- **Entropy:** Invite codes now carry 96 bits of unguessable entropy instead of ~24 bits
- **Format:** Output changes from base-36 (8 chars) to hexadecimal (24 chars); this is longer but still practical for copy-paste and email distribution
- **Reproduction:** Invite codes are no longer reproducible—calling the function twice produces two unique codes
- **Performance:** Negligible overhead; `crypto.randomBytes()` is optimized in Node.js and completes in microseconds
- **Dependencies:** No new external dependencies; `crypto` is a built-in Node.js module
