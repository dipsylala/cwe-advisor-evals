## Verdict

Confirmed. `LoginHandler::handleLogin()` authenticates a user by comparing the submitted password to the stored `password` column with the loose equality operator (`==`).

## Source

`$post['password']`, read from the login form submission at line 20 (`$password = (string) ($post['password'] ?? '');`), flows unmodified into the comparison at line 35.

## Fix

### File: LoginHandler.php
```php
<?php

/**
 * Handles the username/password login form submission for the account
 * portal. Looks up the user by username and checks the submitted
 * password against the stored value.
 */
class LoginHandler
{
    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function handleLogin(array $post): array
    {
        $username = trim($post['username'] ?? '');
        $password = (string) ($post['password'] ?? '');

        if ($username === '' || $password === '') {
            return ['success' => false, 'error' => 'Username and password are required.'];
        }

        $stmt = $this->db->prepare('SELECT id, username, password, role FROM users WHERE username = :username LIMIT 1');
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return ['success' => false, 'error' => 'Invalid username or password.'];
        }

        if (password_verify($password, $user['password'])) {
            if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                $newHash = password_hash($password, PASSWORD_DEFAULT);
                $update = $this->db->prepare('UPDATE users SET password = :password WHERE id = :id');
                $update->execute(['password' => $newHash, 'id' => $user['id']]);
            }

            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];

            return ['success' => true, 'user_id' => $user['id']];
        }

        return ['success' => false, 'error' => 'Invalid username or password.'];
    }
}
```

## Explanation

The original check, `$password == $user['password']`, has two independent problems. First, PHP's `==` performs type-juggling comparisons: if the stored value happens to be a numeric-looking string such as `"0e12345"`, a submitted password of `"0e67890"` (or any other string PHP casts to the same numeric value) evaluates as equal, letting an attacker bypass authentication without knowing the real password ("magic hash" collision). Second, and more fundamentally, comparing against `$user['password']` implies the credential is stored and checked verbatim rather than as a salted hash, and even a strict `===` comparison here would still be a plaintext/reversible-comparison flaw and vulnerable to a timing side channel, since string comparison in PHP is not constant-time.

The fix replaces the equality check with `password_verify($password, $user['password'])`. `password_verify()` performs a constant-time comparison against a password hash produced by `password_hash()` (bcrypt or Argon2 depending on `PASSWORD_DEFAULT`), eliminating both the type-juggling bypass and the timing side channel, and it removes any expectation that the plaintext password is ever stored or compared directly. Because `PASSWORD_DEFAULT` can change as PHP's hashing recommendations evolve, `password_needs_rehash()` is checked on successful login so an account's stored hash is transparently upgraded to the current algorithm/cost without forcing a password reset. This assumes the `users.password` column holds a hash produced by `password_hash()`; if the column currently holds plaintext values, those must be migrated to `password_hash()` output (e.g. in a one-time backfill or on next successful login) for `password_verify()` to succeed.
