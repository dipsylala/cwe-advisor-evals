## Verdict
Confirmed. Session variables are set on line 34 after successful authentication without regenerating the session ID, allowing session fixation attacks where an attacker forces a known session ID before login.

## Source
```php
if (!password_verify($password, $user['password_hash'])) {
    return false;
}

// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;

return true;
```

## Fix
### File: LoginHandler.php
```php
<?php

/**
 * Handles POST /login. Verifies the submitted credentials against the
 * users table and, on success, marks the current session as authenticated.
 */
class LoginHandler
{
    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function handle(string $email, string $password): bool
    {
        $stmt = $this->db->prepare('SELECT id, password_hash FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user === false) {
            // Still verify against a dummy hash so a missing account doesn't
            // return faster than a wrong password.
            password_verify($password, self::dummyHash());
            return false;
        }

        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        // Regenerate session ID to prevent session fixation attacks
        session_regenerate_id(true);

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['authenticated'] = true;

        return true;
    }

    private static function dummyHash(): string
    {
        static $hash = null;
        if ($hash === null) {
            $hash = password_hash('dummy-password-for-timing', PASSWORD_DEFAULT);
        }
        return $hash;
    }
}
```

## Explanation
The fix adds `session_regenerate_id(true)` immediately after successful credential verification and before setting authentication state in the session. This call:
- Generates a new session ID and assigns it to the user
- Discards the old session ID (the `true` parameter deletes the old session file)
- Invalidates any pre-known session ID an attacker may have forced the user to use

Session fixation attacks rely on the attacker controlling the session ID before authentication. Regenerating it after successful login prevents the attacker's pre-session from being reused, ensuring only legitimate logins can access authenticated state.

E:/Github/cwe-advisor/evals/runs-v21/A/287/php/SessionNotRegeneratedAfterLogin.md
