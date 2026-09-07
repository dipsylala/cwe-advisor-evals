## Verdict

exploitable

## Source

Plaintext password submitted via the login form in `$post['password']`, cast to string at line 20.

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
    private string $dummyHash;

    public function __construct(PDO $db)
    {
        $this->db = $db;
        // Generate dummy hash once at initialization with same algorithm as stored hashes
        $this->dummyHash = password_hash('dummy', PASSWORD_DEFAULT);
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
            // Verify against dummy hash to mitigate timing-based user enumeration
            password_verify($password, $this->dummyHash);
            return ['success' => false, 'error' => 'Invalid username or password.'];
        }

        // Use password_verify() for constant-time, secure password comparison
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

The vulnerability at line 35 uses loose equality (`==`) to compare a plaintext password against a stored value. This introduces two related weaknesses: (1) timing attacks, where the `==` operator can execute in variable time depending on how early the comparison fails, allowing an attacker to enumerate valid usernames and guess password prefixes; (2) type juggling with PHP's `==`, where values like `"0e123456..."` and `"0e987654..."` compare as equal because they look like scientific notation. The fix replaces `==` with `password_verify($password, $user['password'])`, which performs constant-time comparison and is the PHP standard for securely verifying hashed passwords. Additionally, when no user is found, the code now calls `password_verify()` against a dummy hash (initialized once in `__construct`) to ensure the unknown-user branch takes the same time as a successful lookup and verification, closing the user-enumeration oracle. The stored password hash should have been generated with `password_hash()` using `PASSWORD_DEFAULT` or `PASSWORD_ARGON2ID`; if it was not, the application must first migrate passwords using `password_hash()` on login when the user verifies successfully.

## Behaviour changes

- Added `$dummyHash` instance variable, initialized once per object in `__construct` by calling `password_hash()`. This variable is never used except to provide constant-time verification on the unknown-user branch, so it has no impact on successful login paths or return values.
- Line 35: Changed `if ($password == $user['password'])` to `if (password_verify($password, $user['password']))`. The `password_verify()` function returns a boolean (same contract as `==`), so the condition behavior is identical when credentials are valid; the difference is that `password_verify()` is constant-time and cannot be fooled by type juggling. Return values and the session_regenerate_id() call remain unchanged.
- Added `password_verify($password, $this->dummyHash)` call on line 32 in the no-user branch. The return value is discarded (the call is for timing only), and the error message and return value of the method remain identical.
