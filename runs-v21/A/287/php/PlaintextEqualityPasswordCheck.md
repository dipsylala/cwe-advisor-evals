## Verdict

CWE-287 (Improper Authentication) confirmed at line 35. The code uses loose equality (`==`) to compare a plaintext user-supplied password against a stored value, enabling type-juggling attacks. Additionally, the comparison mechanism assumes plaintext storage, which violates secure password handling practices.

## Source

**File:** LoginHandler.php  
**Line:** 35  
**Code:**
```php
if ($password == $user['password']) {
```

The vulnerability occurs because:
- Loose equality (`==`) can be bypassed through PHP's type juggling (e.g., `0 == "hash_starting_with_letter"` evaluates to `true`)
- The code does not use `password_verify()`, which is the only secure way to verify passwords stored with `password_hash()`

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

        // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
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

Replace the loose-equality comparison with `password_verify()`, PHP's built-in function for securely validating passwords stored with `password_hash()`. This closes two vectors:

1. **Type juggling bypass:** `password_verify()` performs timing-safe binary comparison, eliminating loose-equality attacks where numeric strings or zero values bypass the check.

2. **Secure password verification:** `password_verify()` is designed for hashed passwords and automatically handles the comparison against the hash algorithm, cost factor, and salt embedded in the hash. This is the only secure way to verify passwords stored with `password_hash()`.

The stored password in the database must have been hashed with `password_hash($password, PASSWORD_BCRYPT)` or a compatible algorithm at registration time. Using `password_verify()` ensures timing-safe comparison and protects against both cryptographic weaknesses and type juggling attacks.

