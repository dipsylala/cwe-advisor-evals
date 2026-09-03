## Verdict

exploitable

## Source

Line 20: `$resetToken = uniqid($prefix, true);`

The `uniqid()` function is not a cryptographic random generator. It generates a token based on the current Unix timestamp and microseconds, formatted as hex: `sprintf("%08x%05x", seconds, microseconds)`. An attacker within the same second (or with knowledge of the server's time) can enumerate possible reset tokens and guess the one issued for a victim account.

## Fix

**Vulnerable code (line 20):**
```php
$resetToken = uniqid($prefix, true);
```

**Fixed code:**
```php
$resetToken = bin2hex(random_bytes(16));
```

## Explanation

Replace `uniqid()` with `bin2hex(random_bytes(16))`, which generates 32 hexadecimal characters carrying 128 bits of entropy from PHP's cryptographically secure random source (`random_bytes()`). This eliminates the predictability of the token. The `random_bytes()` function has been available since PHP 7.0 and is the platform's standard for token generation. Rotating previously issued tokens is necessary because the weak generator has already issued guessable reset tokens in production until this fix is deployed and all outstanding tokens expire or are manually revoked.

## Behaviour changes

The `$prefix` variable derived from `$post['client_nonce']` is no longer prepended to the reset token. Removing this user-controlled prefix is correct here: security-sensitive tokens must derive their unpredictability from the generator alone, not from user input. Allowing a user-supplied nonce to influence the token introduces a new weakness (CWE-330 again: an attacker can supply a guessable nonce), defeating the purpose of cryptographic generation. The token length increases to 32 hex characters, which meets OWASP ASVS's 128-bit entropy floor for non-guessable values.
