## Verdict

Improper authentication due to loose equality comparison in password verification.

## Source

Line 35 in LoginHandler.php uses the loose equality operator (`==`) to compare the submitted password against the stored value:

```php
if ($password == $user['password']) {
```

This allows PHP type juggling to bypass authentication. For example, if the stored password is `"0e123456"` (interpreted as scientific notation for zero), the attacker can submit `"0"` which also evaluates to zero, making the comparison return true.

## Fix

Replace the loose equality operator with strict equality (`===`):

```php
if ($password === $user['password']) {
```

For production code, further strengthen authentication by:
1. Hash passwords at storage time using `password_hash($password, PASSWORD_DEFAULT)` when user account is created or password is changed
2. Verify submitted passwords using `password_verify($password, $user['password'])` instead of direct comparison

## Explanation

Loose equality (`==`) in PHP performs type juggling, converting both operands to the same type before comparison. This creates unintended matches when strings that start with `0e` followed by digits are compared against zero or zero-like values, because PHP interprets them as scientific notation.

The strict equality operator (`===`) prevents type coercion and requires both the value and type to match exactly. This closes the type juggling bypass vector for this specific case.

However, the stronger remediation is to use PHP's password hashing functions. `password_hash()` applies a cryptographically strong algorithm (bcrypt by default) at account creation time, and `password_verify()` safely compares the submitted plaintext password against the stored hash without type juggling vulnerabilities. This approach also protects against database compromise, as the plaintext password cannot be recovered from the hash.
