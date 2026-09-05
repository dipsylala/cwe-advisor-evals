# CWE-287: Improper Authentication - PlaintextEqualityPasswordCheck

## Verdict

Exploitable. The vulnerable code uses loose comparison (`==`) to validate user credentials directly against a plaintext password retrieved from the database. This violates secure password verification practices and introduces both authentication bypass risks and timing-attack vulnerabilities.

## Source

**File**: LoginHandler.php  
**Lines**: 35, 19-20  
**Data Flow**:
- Source: `$post['password']` (user-supplied password from login form at line 20)
- Sink: Line 35 - `if ($password == $user['password'])` - loose comparison against database-stored credential

## Fix

**Vulnerable Code**:
```php
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

    // VULNERABILITY: loose comparison with plaintext credential
    if ($password == $user['password']) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];

        return ['success' => true, 'user_id' => $user['id']];
    }

    return ['success' => false, 'error' => 'Invalid username or password.'];
}
```

**Fixed Code**:
```php
// Define a constant dummy hash (generated once with password_hash)
private const DUMMY_HASH = '$2y$10$N9qo8uLOickgx2ZMRZoMye4FjLEVTQqQ5sIUklb4J6lsSsvqKOYFS';

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

    // Verify password using password_verify on found user
    $hash = $user['password'] ?? self::DUMMY_HASH;
    if (!password_verify($password, $hash)) {
        return ['success' => false, 'error' => 'Invalid username or password.'];
    }

    // Only reach this point if user was found and password verified
    if (!$user) {
        return ['success' => false, 'error' => 'Invalid username or password.'];
    }

    // Rehash if needed
    if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
        $stmt = $this->db->prepare('UPDATE users SET password = :password WHERE id = :id');
        $stmt->execute(['password' => password_hash($password, PASSWORD_DEFAULT), 'id' => $user['id']]);
    }

    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];

    return ['success' => true, 'user_id' => $user['id']];
}
```

## Explanation

The fix replaces loose comparison (`==`) with `password_verify()`, which is a timing-safe hash comparison function designed for authentication. The key changes are:

1. **Secure verification with `password_verify()`**: The submitted password is verified against a stored bcrypt hash using `password_verify($password, $hash)`, which performs constant-time comparison and safely handles bcrypt hashes.

2. **Timing-attack mitigation using dummy hash**: When a user is not found, the code verifies the submitted password against a `DUMMY_HASH` constant (a pre-generated bcrypt hash). This ensures that both the "user not found" and "wrong password" branches take approximately the same time, preventing attackers from enumerating valid usernames through response-time analysis.

3. **Automatic hash upgrade**: The `password_needs_rehash()` check ensures older password hashes (using weaker algorithms or parameters) are automatically upgraded to `PASSWORD_DEFAULT` on login, maintaining a modern security baseline without forcing users to reset their passwords.

4. **Secure password storage**: Passwords must be hashed with `password_hash($password, PASSWORD_DEFAULT)` at registration/password-change time, not stored in plaintext. This requires a corresponding database change to store bcrypt hashes (minimum 60 characters for `$2y$` format).

## Behaviour changes

1. **Dummy hash constant definition**: A class constant `DUMMY_HASH` is defined once with a pre-generated bcrypt hash. This is a one-time setup cost with no runtime overhead beyond the constant definition.

2. **Return value preserved**: The method still returns the same structure (`['success' => bool, ...]` with user_id or error message) - no changes to the API contract.

3. **Session regeneration preserved**: `session_regenerate_id(true)` is still called on successful login, maintaining CSRF protection and session fixation mitigation.

4. **New hash upgrade path**: On successful login, if the stored password hash is using outdated parameters (detected by `password_needs_rehash()`), a new hash is generated and stored. This is an additional database write on some logins but is necessary for long-term security as password-hashing algorithms evolve. The performance cost is negligible compared to `password_verify()`.

5. **Database schema requirement**: Passwords must be stored as bcrypt hashes (60+ characters), not plaintext. The database must be migrated to use `password_hash()` values for all existing passwords before deploying this fix, or all existing users will be unable to log in.

