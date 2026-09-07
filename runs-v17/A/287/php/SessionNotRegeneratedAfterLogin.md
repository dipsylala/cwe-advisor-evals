## Verdict

CONFIRMED — Session ID is not regenerated after successful authentication. An attacker can establish a session, trick a user into logging in via that session, and then hijack the authenticated session using the pre-established session ID.

## Source

The vulnerability occurs in `LoginHandler.php` at line 34, where the authenticated user ID is stored in the session without first regenerating the session ID. The authentication check succeeds at line 29, but the code proceeds directly to set session variables without calling `session_regenerate_id()`.

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

The fix adds `session_regenerate_id(true)` immediately after the password verification succeeds and before storing authentication state in the session. The `true` parameter ensures the old session file is deleted, preventing an attacker from reusing the pre-login session ID.

Session fixation attacks exploit the reuse of a known session ID across the authentication boundary. By regenerating the session ID upon successful login, the attacker's pre-established session identifier becomes invalid, and only the legitimate user knows the new session ID created during the login process.

This is a standard defense-in-depth measure required by CWE-287 guidance: always regenerate session identifiers after authentication state changes to prevent attackers from hijacking sessions they crafted beforehand.
