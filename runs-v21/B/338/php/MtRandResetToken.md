## Verdict

Exploitable. The password reset token is generated using `mt_rand()`, a cryptographically weak PRNG with very low entropy (~20 bits from a range of 0–999,999). The seed value is user-supplied from an HTTP request, making the token completely predictable. An attacker can enumerate valid reset tokens or predict them outright, gaining unauthorized password reset capability for any user.

## Source

User-supplied input: `$request['client_seed']` passed to `mt_rand()` as the minimum bound.

## Fix

### File: MtRandResetToken.php

```php
<?php

// Handles a "forgot password" request and emails the user a reset link.
function handlePasswordResetRequest(PDO $db, array $request): void
{
    $email = $request['email'] ?? '';

    $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $userId = $stmt->fetchColumn();

    if ($userId === false) {
        return;
    }

    // Generate a cryptographically secure random token using random_bytes
    $token = bin2hex(random_bytes(32));

    $update = $db->prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?');
    $update->execute([$token, time() + 3600, $userId]);

    mail($email, 'Password Reset', 'Use this code to reset your password: ' . $token);
}
```

## Explanation

The vulnerable code used `mt_rand($seed, $seed + 999999)` to generate a password reset token, where `$seed` is attacker-controlled. `mt_rand()` is a cryptographically weak PRNG (Mersenne Twister) with recoverable state, and the range limitation provides only ~20 bits of entropy. The fix replaces this with `bin2hex(random_bytes(32))`, which generates a 64-character cryptographically secure token with 256 bits of entropy directly from the operating system's entropy source. This eliminates both the weak PRNG and the predictable range, making the token computationally infeasible to guess or brute-force. The `random_bytes()` function is available in PHP 7.0+ and does not require any external dependencies.

## Behaviour changes

**Token format change**: The token is now a 64-character hexadecimal string instead of an integer in the range `[0, 999999]`. The database column must accommodate this (minimum `varchar(64)`). The email message and any comparison logic that handles reset tokens will accept the longer string without issues. **Reason**: Cryptographically secure tokens require much higher entropy; a 6-digit number cannot provide adequate protection for a password reset operation.

**Removed user-controlled seed**: The `$request['client_seed']` variable is no longer used. **Reason**: Seeding a PRNG with user-supplied data is a critical security vulnerability and serves no legitimate purpose here; the operating system's entropy source provides better randomness automatically.

**No loss of functionality**: The `random_bytes()` function is seeded by the OS and requires no explicit initialization or seeding logic. The token is still stored in the database and sent via email, with no change to those operations. **Reason**: `random_bytes()` handles initialization and entropy management transparently and securely.

