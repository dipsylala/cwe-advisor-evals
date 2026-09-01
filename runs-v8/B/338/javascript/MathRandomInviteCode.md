## Verdict

Valid. The finding is a real vulnerability.

## Source

Line 18 uses `Math.random().toString(36).slice(2, 10)` to generate an invite code. This code is security-sensitive: it acts as a single-use access token that grants workspace membership, and is therefore not suitable for non-cryptographic randomness. An attacker can predict the sequence of generated codes and forge valid invites for any email address.

## Fix

Replace line 18:

```javascript
  const inviteCode = Math.random().toString(36).slice(2, 10);
```

With:

```javascript
  const crypto = require('crypto');
  const inviteCode = crypto.randomBytes(16).toString('hex');
```

Or, if `crypto` is already imported at the top of the file, use only:

```javascript
  const inviteCode = crypto.randomBytes(16).toString('hex');
```

## Explanation

`Math.random()` is a general-purpose PRNG designed for non-security uses like animations or UI shuffling. It produces predictable values that an attacker can reproduce. The fix replaces it with `crypto.randomBytes(16)`, which generates 128 bits of cryptographically secure random data—sufficient entropy for session tokens and access codes. The `.toString('hex')` conversion produces a 32-character hexadecimal string, which is longer than the original 8-character code but provides the required security strength and remains URL-safe.

## Behaviour changes

- **Predictability**: Invite codes are now cryptographically unpredictable; previously they could be guessed by an attacker.
- **Length**: Codes are now 32 hex characters (e.g., `a1b2c3d4e5f6789...`) instead of 8 base36 characters; the API response format remains unchanged (still a string).
- **Dependencies**: No new external dependencies required; `crypto` is a Node.js standard library module available in all supported LTS versions.
- **Functional impact**: No change to API contract or request/response structure; only the internal randomness source is strengthened.
- **Performance**: Negligible; `crypto.randomBytes()` is a single system call.
