## Verdict

CWE-338 confirmed. The function uses `mt_rand()`, a cryptographically weak PRNG, seeded with attacker-controlled input to generate a password reset token—a security-sensitive value that requires cryptographic strength.

## Source

Line 16–18: User-supplied `$seed` value passed to `mt_rand()` to generate password reset token.

```php
$seed = $request['client_seed'] ?? 0;
$token = mt_rand($seed, $seed + 999999);
```

## Fix

Replace the weak PRNG call with cryptographically secure random bytes. Remove dependence on user-supplied seed:

```php
$token = bin2hex(random_bytes(16));
```

## Explanation

`mt_rand()` is a general-purpose PRNG unsuitable for cryptographic use; seeding it with attacker-controlled values makes the output predictable. `random_bytes(16)` generates 16 bytes of cryptographically secure random data from the OS entropy pool; `bin2hex()` encodes it as a 32-character hex string suitable for transmission via email and database storage. This eliminates both the weak generator and the predictable seeding pattern, providing an unpredictable, long-lived token resistant to brute-force attacks.

## Behaviour changes

Token format changes from a 6–7 digit integer to a 32-character hexadecimal string. Password reset emails now send a longer token, and the database schema must support storing this as a string (VARCHAR or TEXT). The reset token is now cryptographically unpredictable, eliminating the predictability vulnerability.

