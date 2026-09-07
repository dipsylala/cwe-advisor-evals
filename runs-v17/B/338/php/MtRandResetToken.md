## Verdict
Exploitable

## Source
`$request['client_seed']` (line 16, user-controllable parameter)

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

    // CWE-338 fix: Use random_bytes() for cryptographically secure token generation
    $token = bin2hex(random_bytes(32));

    $update = $db->prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?');
    $update->execute([$token, time() + 3600, $userId]);

    mail($email, 'Password Reset', 'Use this code to reset your password: ' . $token);
}
```

## Explanation
The original code used `mt_rand()`, a cryptographically weak PRNG, to generate a password reset token. This is a high-severity vulnerability because password reset tokens are security-critical: predicting a valid token grants an attacker the ability to reset any user's password. Additionally, the seed was derived from user input (`$request['client_seed']`), further compromising the token's unpredictability. The fix replaces this with `random_bytes(32)`, which generates 32 bytes from the operating system's cryptographically secure random source, encoded as a 64-character hexadecimal string. This provides 256 bits of entropy and is computationally infeasible to predict or reproduce.

## Behaviour changes
The token format changes from a small integer (at most 999,999 range) to a 64-character hexadecimal string. This is a larger value suitable for secure token storage and comparison. The database column and any token validation logic must accommodate the new format, but the token is still a simple string suitable for database storage and email transmission. No API semantics change; the value is still passed to the database and email as before.
