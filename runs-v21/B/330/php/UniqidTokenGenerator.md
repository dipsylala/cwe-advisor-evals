## Verdict
Exploitable

## Source
Line 18: `$prefix = $post['client_nonce'] ?? ''` — attacker-controlled from HTTP POST data

## Fix

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

    // Fixed: Replace uniqid() with cryptographically secure random_bytes()
    $resetToken = bin2hex(random_bytes(16));

    $update = $db->prepare('UPDATE users SET reset_token = :token, reset_requested_at = NOW() WHERE id = :id');
    $update->execute(['token' => $resetToken, 'id' => $userId]);

    mail($email, 'Password reset', 'Your reset link: https://example.com/reset?token=' . $resetToken);
}
```

## Explanation
`uniqid()` generates tokens based on the current time formatted with microsecond precision, making them derivable from observable system state rather than cryptographically random. Line 20 replaced this with `bin2hex(random_bytes(16))`, which produces 32 hexadecimal characters (128 bits of entropy) from PHP's cryptographic random-byte source. This eliminates the time-based predictability and meets the OWASP ASVS minimum entropy floor for security tokens. The token is now unpredictable even if an attacker observes the approximate time of the reset request.

## Behaviour changes
- The `$prefix` parameter from `$post['client_nonce']` is no longer used in the token generation. This is intentional: user-controlled input cannot add cryptographic entropy and only increases predictability. The token is now entirely independent of client nonce values.
- The function may now throw `Random\RandomException` (PHP 8.2+) or `Exception` (PHP 7.0-8.1) if the system entropy source is unavailable. This fails closed (secure failure) rather than silently falling back to a weak algorithm.
- Token format is now pure hexadecimal (characters 0-9a-f). Previously `uniqid()` produced lowercase hex with a varying prefix; the new format is uniform 32 hex characters with no prefix.
- No behavioral change to the database or email functionality—the token is still passed to the same queries and email template.
