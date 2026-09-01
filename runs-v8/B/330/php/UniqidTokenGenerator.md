## Verdict

Confirmed. Line 20 uses `uniqid()` to generate a security-sensitive password reset token. `uniqid()` is not a cryptographic random generator and its output is time-based and predictable, allowing attackers to forge valid reset tokens.

## Source

Line 18 receives `$post['client_nonce']` from untrusted POST parameters. Line 20 passes this as the `$prefix` parameter to `uniqid()`.

## Fix

Replace the vulnerable token generation on line 20:

```php
// Vulnerable:
$resetToken = uniqid($prefix, true);

// Fixed:
$resetToken = bin2hex(random_bytes(16));
```

The `$prefix` variable should not be used. It comes from user input and neither salts a weak generator nor improves security.

## Explanation

`uniqid()` produces output derived from the current time and microsecond precision, making tokens predictable to attackers who know or can infer the timestamp of token generation. The second parameter (`true`) adds only 8 additional hex digits of weak output, insufficient to prevent forgery.

The fix replaces the generator with `random_bytes(16)`, PHP's cryptographic random source available since PHP 7.0. `bin2hex()` encodes the 16 bytes as 32 hexadecimal characters, carrying 128 bits of entropy—the minimum required by OWASP ASVS for non-guessable values.

## Behaviour changes

- Token format changes from time-based (e.g., `"prefix66f1a2ab50015"`) to hex-encoded random bytes (e.g., `"a3f7c9e2b1d4f6a8c2e5b7d9f1a3c5e7"`).
- Token length is fixed at 32 characters instead of variable based on prefix length.
- Tokens become cryptographically unpredictable, preventing forgery attacks.
- Performance impact is negligible; `random_bytes()` is optimized for security use.
- Previously issued tokens remain valid until they expire or are explicitly revoked—no rotation of old tokens is required because `random_bytes()` output has never been weak.
