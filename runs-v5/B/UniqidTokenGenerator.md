## Verdict

- **cwe_id**: CWE-330 (Use of Insufficiently Random Values)
- **location**: `UniqidTokenGenerator.php:20`
- **verdict**: exploitable
- **confidence**: high

## Source

- **source**: `$post['email']` and `$post['client_nonce']` (POST body of `POST /password-reset/request`); the account lookup at line 9-11 is a DB read, not the weakness.
- **sink**: `uniqid($prefix, true)` at line 20. `uniqid()` is not a PRNG - its base output is `sprintf("%08x%05x", seconds, microseconds)`, the current time formatted, not a random draw. The `more_entropy` flag (`true`) appends a combined-LCG suffix, which does not change this: the value is still derivable from the request time rather than recoverable only from generator state.
- **flow**: `$resetToken` from the sink is written to `users.reset_token` (line 23) and emailed to the user inside a reset URL (line 25). Anyone who can bound the request's timestamp (visible via the `Date` response header, or by timing the request) can brute-force the microsecond and LCG components and recover a working reset token, giving full account takeover.

## Fix

No library change is needed - `random_bytes()` is a PHP core function available since PHP 7.0.

Vulnerable code:

```php
$prefix = $post['client_nonce'] ?? '';
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
$resetToken = uniqid($prefix, true);
```

Fixed code:

```php
// 16 random bytes -> 32 hex characters = 128 bits of entropy, meeting the OWASP ASVS floor for a non-guessable token.
$resetToken = bin2hex(random_bytes(16));
```

## Explanation

`uniqid()` is time-based, not random, so no amount of prefixing or the `more_entropy` flag makes its output unpredictable - the fix has to replace the generator, not season its input. `random_bytes()` is PHP's CSPRNG-backed byte source; encoding 16 bytes as hex yields a 32-character token carrying 128 bits of entropy, meeting the ASVS floor for non-guessable tokens, and it fails closed (throws `Random\RandomException` / `Exception` on entropy-source failure) rather than silently degrading. The downstream sink contract is unchanged: `$resetToken` is still a string assigned to `reset_token` and interpolated into the same email URL, so no caller-visible shape changes.

This code-level fix only secures newly issued tokens. Any reset token already stored via the old `uniqid()` call remains guessable until it is rotated or expires; if this account-recovery flow is deployed already, existing `reset_token` values should be invalidated (e.g. bulk NULL-out or forced expiry) as a follow-up outside this diff.

## Behaviour changes

- Removed `$prefix = $post['client_nonce'] ?? '';`. It only fed the removed `uniqid()` call as a cosmetic prefix and added no entropy; `client_nonce` is no longer read from the request. Nothing else in the function consumed it, so this is safe.
- Token length and character set change from `uniqid()`'s ~23-character hex-plus-dot string (with `more_entropy`) to a fixed 32-character lowercase-hex string. Both are stored in and compared against the same `reset_token` column and interpolated into the same URL format, so no schema or parsing change is required unless a column length constraint is stricter than 32 characters (unseen in this file).
- Existing tokens issued by the old `uniqid()` call are not rotated by this fix - see rotation note in Explanation. This is an operational action, not a code change, and is called out rather than silently left undone.
