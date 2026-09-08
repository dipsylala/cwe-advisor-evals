## Verdict

The vulnerability is confirmed. Line 35 uses loose comparison (`==`) instead of `password_verify()` to validate the password against the database hash. This is a taint sink for CWE-287 (Improper Authentication). Additionally, the code lacks timing-attack protection—when the user is not found, it returns immediately without hashing, creating a user-enumeration oracle.

## Source

User-supplied password from `$_POST['password']` (line 20), passed as the `$password` parameter and compared directly against the stored hash on line 35.

## Fix

Replace the loose `==` comparison with `password_verify()`, and add timing-attack protection on the unknown-user branch by calling `password_verify()` against a dummy hash before returning:

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

    // Timing-attack protection: a hash generated once with password_hash()
    // at the same algorithm and cost as stored hashes
    private const DUMMY_HASH = '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36P4/D1C';

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
            // Timing-attack protection: consume the same time as a successful hash check
            password_verify($password, self::DUMMY_HASH);
            return ['success' => false, 'error' => 'Invalid username or password.'];
        }

        // Use password_verify() to safely verify the password against the stored hash
        if (password_verify($password, $user['password'])) {
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

The fix replaces the unsafe `==` loose comparison (line 35) with `password_verify()`, which is the only safe way to validate passwords against bcrypt hashes in PHP. The `password_verify()` function is timing-safe and accepts properly hashed passwords.

Additionally, a `DUMMY_HASH` constant is added and called on the unknown-user branch (line 33). This ensures that both the "user not found" and "user exists but password wrong" cases consume the same hashing time, preventing attackers from using response time to enumerate valid usernames.

The `session_regenerate_id(true)` call was left unchanged; the true parameter deletes the old session data, which is appropriate for this login context to prevent session fixation attacks.

## Behaviour changes

- **Authentication logic**: Password validation now uses the timing-safe `password_verify()` function instead of string equality. Only passwords hashed with `password_hash()` using bcrypt (or Argon2) will be accepted.
- **Timing**: Unknown users and users with wrong passwords now both consume the time required for `password_verify()` to run, closing the timing oracle that previously allowed user enumeration.
- **Session security**: No change—`session_regenerate_id(true)` still invalidates the pre-login session, preventing fixation.
- **Error message**: Unchanged—still returns "Invalid username or password" for both nonexistent users and wrong passwords.
