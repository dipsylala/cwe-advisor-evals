## Verdict

EXPLOITABLE. The application uses `uniqid()` to generate password reset tokens. `uniqid()` generates values based on the current time in microseconds, not from a cryptographic source. An attacker can predict reset tokens by knowing approximate request timing, allowing unauthorized account takeover.

## Source

User request → `POST` body parameter `client_nonce` (line 18, assigned to `$prefix`) → passed to `uniqid()` sink on line 20.

The `$prefix` parameter further weakens the token by allowing user-supplied input to influence token generation.

## Fix

Replace `uniqid()` with `random_bytes()` encoded as hex. Remove the unused `$prefix` variable since the token should not be influenced by user input.

### File: UniqidTokenGenerator.php

```php
<?php

// Handles POST /password-reset/request
// Generates a reset token for the account matching the submitted email.
function handlePasswordResetRequest(array $post, PDO $db): void
{
    $email = $post['email'] ?? '';

    $stmt = $db->prepare('SELECT id FROM users WHERE email = :email');
    $stmt->execute(['email' => $email]);
    $userId = $stmt->fetchColumn();

    if ($userId === false) {
        http_response_code(200);
        return;
    }

    // Generate a cryptographically random reset token: 32 hex characters = 128 bits entropy
    $resetToken = bin2hex(random_bytes(16));

    $update = $db->prepare('UPDATE users SET reset_token = :token, reset_requested_at = NOW() WHERE id = :id');
    $update->execute(['token' => $resetToken, 'id' => $userId]);

    mail($email, 'Password reset', 'Your reset link: https://example.com/reset?token=' . $resetToken);
}
```

## Explanation

`uniqid()` generates tokens based on the current time formatted as microseconds. An attacker who knows approximate request timing can predict valid reset tokens, making the fix load-bearing for account security. The fix replaces the time-based generator with `random_bytes()`, which is PHP's cryptographic random source available since PHP 7.0. The bytes are hex-encoded to produce a 32-character token string carrying 128 bits of entropy (meeting OWASP ASVS requirements). The `$prefix` variable is removed because it was only used in the weak generator and allowing user input to influence token generation introduces additional attack surface.

## Behaviour changes

- Token format changes from `uniqid()` format (e.g., `4d1f6a2c5b8e9a3f`) to hex-encoded random bytes (e.g., `a3f8e2c5d1b9f7c6e4a2d8b1f6c9a3e5`)
- Token length remains similar (32 hex characters vs. ~28-30 chars from `uniqid()`)
- The application no longer accepts user-supplied `client_nonce` parameter for token generation
- Token is now cryptographically unpredictable, eliminating the CWE-330 exposure
- Rotation recommended: existing reset tokens generated with `uniqid()` remain valid in the database until natural expiration; consider invalidating them during deployment if exposure window is a concern
