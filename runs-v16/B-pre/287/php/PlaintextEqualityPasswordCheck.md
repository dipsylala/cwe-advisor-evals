## Verdict

Real issue, fix required.

## Source

User-submitted password from `$_POST['password']` (line 20), stored plaintext in the database as `$user['password']` (line 28).

## Fix

Line 35 uses the loose-equality operator `==` to compare plaintext passwords. Replace with cryptographic comparison using `password_verify()`:

```php
// Before (line 35):
if ($password == $user['password']) {

// After:
if (password_verify($password, $user['password'])) {
```

Additionally, add dummy-hash verification on the lookup-miss branch to defeat user-enumeration timing attacks:

```php
// After line 30, before the early return on line 31:
if (!$user) {
    password_verify($password, '$2y$10$disabledAccountHashForTimingAttackDefense');
    return ['success' => false, 'error' => 'Invalid username or password.'];
}
```

These changes also require that the application hash all passwords with `password_hash()` when storing them:

```php
// When storing a new password (not shown in this handler):
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
// Store $hashedPassword in the database, not $password
```

## Explanation

The vulnerability is a combination of two flaws: plaintext password storage and unsafe comparison. Line 35's `==` operator performs loose equality, which is both unsafe for cryptographic comparison (type juggling can bypass the check) and not timing-resistant, allowing attackers to guess passwords faster. The stored password should be hashed using `password_hash()` with a cost-adaptive algorithm like bcrypt or Argon2, and verification should use `password_verify()`, which implements constant-time comparison to prevent timing-based password guessing.

The dummy-hash check on the miss branch closes a user-enumeration oracle: when no user exists, the application still performs a full `password_verify()` hash computation (taking milliseconds), which makes the timing indistinguishable from a valid user with a wrong password. Without this branch, an attacker can distinguish "user not found" from "wrong password" by timing differences of 100+ milliseconds.

## Behaviour changes

- Passwords must be stored as hashes (via `password_hash()`), not plaintext. Any existing plaintext passwords must be migrated before this fix is deployed.
- Login latency increases slightly (5-10ms) due to the cost of `password_verify()`, which is intentional: the work factor deters brute-force attacks.
- The `password_verify()` timing is now constant regardless of password length (within normal bounds), eliminating a timing-based attack vector.
- Timing is now uniform whether the user exists with a wrong password or does not exist at all, eliminating user enumeration via response time.
