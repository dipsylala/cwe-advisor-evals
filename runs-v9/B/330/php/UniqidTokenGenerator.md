## Verdict

Exploitable. Confidence: high.

`handlePasswordResetRequest()` builds the password-reset token entirely from `uniqid($prefix, true)` (line 20). PHP's manual defines `uniqid()`'s base output as `sprintf("%08x%05x", seconds, microseconds)` - the current time, not a random draw. The `more_entropy = true` flag appends an `lcg_value()`-derived suffix, and `lcg_value()` itself is a weak, non-cryptographic generator (deprecated as of PHP 8.4 for being "broken in multiple ways"). Neither component supplies unpredictable, attacker-unguessable output. The `$prefix` argument comes from `$post['client_nonce']`, which is attacker-controlled and defaults to an empty string - it does not add entropy either way; concatenating it in front of the time-based value changes the string's appearance without changing its guessability.

An attacker who knows or narrows down the request's timestamp (visible via the HTTP `Date` response header, or brute-forced over the small microsecond space) can reconstruct or enumerate the token, request a password reset for a victim's email, and take over the account before the legitimate user acts on it - the token is written straight to `reset_token` and emailed as a reset link with no other verification step.

## Source

- Attacker-influenced input: `$post['client_nonce']` (line 18), submitted directly on `POST /password-reset/request`.
- Root cause: `uniqid()` itself (line 20) - a time-based identifier, not a randomness source. Even with the client-controlled prefix removed, `uniqid(..., true)`'s own output remains derivable from the request time.
- Sink: `$resetToken` is persisted to `users.reset_token` (line 23) and appended to a mailed reset URL (line 25), so a guessed value is directly usable to reset the account's password.

## Fix

Vulnerable code:

```php
$prefix = $post['client_nonce'] ?? '';
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
$resetToken = uniqid($prefix, true);
```

Fixed code:

```php
// SAST FINDING (CWE-330) resolved: cryptographically secure token, no time-derived or client-supplied material.
$resetToken = bin2hex(random_bytes(16));
```

Library recommendation: none needed - `random_bytes()` is a PHP core function available since PHP 7.0, requiring no dependency addition or version bump.

## Explanation

The fix replaces the time-based `uniqid()` call with `random_bytes(16)` from PHP's CSPRNG, hex-encoded to a 32-character token carrying 128 bits of entropy - meeting the OWASP ASVS floor for a non-guessable value. `random_bytes()` fails closed (throws `Random\RandomException` on PHP 8.2+, or a plain `Exception` on 7.0-8.1) rather than silently returning a weak value, so no fallback to a weaker generator should ever be added around it. The client-supplied `client_nonce` is dropped entirely: `random_bytes()` takes no prefix argument, and mixing attacker-controlled input into a security token added no entropy in the original code, so removing it is inherent to adopting the safe API rather than a separate change.

## Behaviour changes

- **Token shape**: token is now always exactly 32 lowercase hex characters (was a variable-length string starting with the caller-supplied `client_nonce` followed by `uniqid()`'s hex time/entropy output). The `reset_token` column must accommodate at least 32 characters - it already stored the longer `uniqid()` output, so no schema change is expected, but confirm the column width before deploying.
- **`client_nonce` no longer used**: the value submitted in `$post['client_nonce']` is no longer read or reflected into the token. It was attacker-controlled and added no security value, so this narrows behavior only in the sense of dropping an unused input, not in any way relied on by legitimate callers.
- **New failure mode**: `random_bytes()` can throw on catastrophic randomness failure, which `uniqid()` never did. This is intentional fail-closed behavior per the platform guidance and is not caught here; if the caller (the HTTP layer) has no existing handler for uncaught exceptions from this function, a 500 response on that rare failure is the correct outcome rather than issuing a weak token.
- **Rotation not covered by this change**: this fix only affects tokens generated going forward. Any `reset_token` values already issued by the vulnerable `uniqid()` call remain guessable and valid until they expire or are used; invalidating or rotating those existing tokens is a separate operational step this code change does not perform.
- No change to control flow, the DB update statement, the email sent, or error handling elsewhere in the function.
