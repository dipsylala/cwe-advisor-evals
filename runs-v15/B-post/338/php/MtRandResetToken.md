## Verdict

Exploitable. The application generates password reset tokens using `mt_rand()` seeded with user-controlled input, creating a highly predictable security-critical value.

## Source

User-supplied `client_seed` parameter from the request array on line 16:
```php
$seed = $request['client_seed'] ?? 0;
```

## Fix

**Vulnerable code (line 18):**
```php
$token = mt_rand($seed, $seed + 999999);
```

**Fixed code:**
```php
$token = bin2hex(random_bytes(16));
```

Replace the weak PRNG call with a cryptographically secure alternative. `random_bytes(16)` generates 128 bits of entropy and `bin2hex()` converts it to a 32-character hexadecimal string suitable for token storage and transmission.

## Explanation

`mt_rand()` is a general-purpose PRNG, not cryptographically secure, and seeding it with user-supplied input makes token prediction trivial. Attackers observing or controlling the `client_seed` parameter can enumerate the entire token space (just 1 million possibilities) or predict the exact token if they know the seed value. Password reset tokens are security-critical: guessing one grants account takeover. The fix replaces this with `random_bytes()`, PHP's cryptographically secure random source seeded by the operating system, generating tokens with computational infeasibility to guess or predict. The `bin2hex()` encoding creates a printable string format compatible with email transmission and database storage.

## Behaviour changes

- **Token format**: Changes from a 7-digit number (range `seed` to `seed + 999999`) to a 32-character hexadecimal string.
- **Token entropy**: Increases from negligible (user can control or predict the seed, range is only 1 million) to 128 bits of cryptographic entropy.
- **Predictability**: User input no longer influences token generation in any way.
- **Database compatibility**: The `reset_token` column must accommodate a 32-character string instead of a numeric value. If currently defined as `INT` or `BIGINT`, it requires schema migration to `CHAR(32)` or `VARCHAR(32)`. If the column is already `VARCHAR` or `TEXT`, no schema change is required.
- **Functional impact on legitimate use**: Password reset links will now contain longer, alphanumeric tokens instead of short numeric codes. Email delivery and UI handling must accommodate the new format (32 hex characters instead of 7 digits).
