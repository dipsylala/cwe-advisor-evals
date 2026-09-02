## Verdict

The finding is valid. Line 20 uses `uniqid()` to generate a password reset token, but `uniqid()` produces time-based identifiers derivable from microsecond precision, not cryptographic randomness. An attacker can predict valid reset tokens without guessing the `$prefix` input.

## Source

Line 20:
```php
$resetToken = uniqid($prefix, true);
```

The `$prefix` parameter (line 18, from untrusted `$post['client_nonce']`) does not add entropy; it is a fixed or attacker-supplied prefix prepended to a time-derived value. The second argument `true` requests additional entropy from `uniqid()`, but `uniqid()` embeds only the current time, so this still does not produce cryptographic randomness.

The token is stored in the database and sent in a password reset email, where its unpredictability is load-bearing.

## Fix

```php
$resetToken = bin2hex(random_bytes(16));
```

Replace the entire `uniqid()` call with `bin2hex(random_bytes(16))`. This generates 16 cryptographically random bytes and encodes them as 32 hexadecimal characters (128 bits of entropy).

The `$prefix` parameter and its derivation (line 18) can be removed; it does not contribute to security.

## Explanation

`uniqid()` is not a PRNG. It formats the current Unix timestamp and microseconds as `sprintf("%08x%05x", seconds, microseconds)`. This value is deterministic and easily guessable given knowledge of the approximate time the token was issued—a critical flaw for a password reset token, which must be impossible to forge.

`random_bytes(16)` is PHP's cryptographic random-bytes generator (available since PHP 7.0). It draws from the OS kernel's entropy pool and produces values that cannot be predicted even with knowledge of the time or the application's state. Encoding the 16 bytes as hexadecimal yields a 32-character token suitable for storage and transmission.

The fix eliminates the guessability; an attacker can no longer predict valid reset tokens by iterating over timestamps near the time the request was issued.

## Behaviour changes

- Reset tokens are now cryptographically random instead of time-derived.
- Token format is 32 hexadecimal characters (same length and character set as the original with `true` flag, which appended microseconds in hex).
- No change to database schema, email template, or token validation logic—the token is used as an opaque string in all downstream operations.
- The `$post['client_nonce']` parameter is no longer used; it can be removed or retained for backward compatibility if the API still accepts it.
