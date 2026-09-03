## Verdict

The finding is confirmed. Line 18 uses `mt_rand()` for generating a password reset token, which is cryptographically weak. The Mersenne Twister algorithm is not suitable for security-sensitive operations, and the use of a user-controlled seed further weakens the generator.

## Source

**File:** `MtRandResetToken.php`  
**Line:** 18  
**Vulnerable Code:**
```php
$token = mt_rand($seed, $seed + 999999);
```

The token is used as a password reset code (line 23) and stored in the database (line 21). An attacker can predict or brute-force valid tokens because:
1. `mt_rand()` output follows a predictable sequence after the seed is known
2. The range is limited to 1,000,000 possible values
3. The seed is derived from untrusted client input

## Fix

Replace `mt_rand()` with `random_bytes()` to generate a cryptographically secure token:

```php
$token = bin2hex(random_bytes(32));
```

This generates a 64-character hexadecimal string (256 bits of entropy), making brute-force attacks computationally infeasible. The updated code:

```php
function handlePasswordResetRequest(PDO $db, array $request): void
{
    $email = $request['email'] ?? '';

    $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $userId = $stmt->fetchColumn();

    if ($userId === false) {
        return;
    }

    $token = bin2hex(random_bytes(32));

    $update = $db->prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?');
    $update->execute([$token, time() + 3600, $userId]);

    mail($email, 'Password Reset', 'Use this code to reset your password: ' . $token);
}
```

## Explanation

`mt_rand()` implements the Mersenne Twister PRNG, which is fast but predictable—designed for simulations and statistical work, not cryptography. Once the internal state is known (which can be determined from a small number of outputs), all future values become predictable.

`random_bytes()` (available in PHP 7.0+) draws from the OS's cryptographically secure random source:
- On Linux/macOS: `/dev/urandom`
- On Windows: `CryptGenRandom()`

This ensures each token is drawn from a uniform distribution with sufficient entropy to prevent enumeration. Converting to hexadecimal with `bin2hex()` makes the token human-readable while retaining cryptographic strength.

The client seed on line 16 should not influence token generation—security-sensitive values must not depend on user input for their randomness.
