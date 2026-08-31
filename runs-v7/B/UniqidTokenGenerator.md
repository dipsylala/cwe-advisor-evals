## Verdict

CWE-330 confirmed. `uniqid()` generates reset tokens from the current timestamp with microsecond precision, not cryptographic randomness. The OWASP Manual and PHP documentation both forbid its use for security-sensitive values.

## Source

Line 20: `$resetToken = uniqid($prefix, true);`

The `uniqid()` function produces a value derivable from the current time rather than from a cryptographic generator. The `true` parameter adds entropy but does not make it suitable for a security token. Additionally, the user-controlled `$prefix` parameter (`$post['client_nonce']`) influences the output, further weakening it.

## Fix

Replace line 20 with:

```php
$resetToken = bin2hex(random_bytes(16));
```

`random_bytes(16)` generates 16 bytes (128 bits) of cryptographic entropy via the platform's secure generator (available since PHP 7.0). `bin2hex()` encodes it as 32 hex characters for storage and transmission. This removes the timestamp-based derivability and eliminates the user-supplied prefix influence entirely.

## Explanation

`uniqid()` is unsuitable for security tokens because it is time-based and predictable. The fix replaces it with `random_bytes()`, which draws from the operating system's cryptographic random source (`/dev/urandom` on Unix, `CryptGenRandom` on Windows). The 128-bit entropy floor meets OWASP ASVS requirements for non-guessable values. The hex encoding keeps the value as a string compatible with the existing database and email code paths.

The user-controlled `$prefix` is removed entirely; security tokens must not incorporate untrusted input. If the application needs to track a client nonce separately (for replay detection or logging), store it in a separate field, not as part of the token.

## Behaviour changes

- **Token format**: Changes from 13-character alphanumeric (e.g. `5f2c4e3b1a2b5`) to 32-character hexadecimal (e.g. `a7f3c9e1b2d4f5a8c6e9d1f4b5a2c9e1`)
- **Token entropy**: Increases from ~40 bits (time-based) to 128 bits (cryptographic)
- **Predictability**: Tokens are no longer derivable from wall-clock time
- **User input influence**: User-supplied nonce is no longer incorporated into the token
- **Database impact**: Existing reset tokens remain valid until they expire; no rotation required for tokens issued after this fix deploys
- **Exception handling**: `random_bytes()` throws `Exception` (PHP <8.2) or `Random\RandomException` (PHP 8.2+) on failure; the application does not currently handle this, but it is the correct fail-closed behavior per the PHP manual
