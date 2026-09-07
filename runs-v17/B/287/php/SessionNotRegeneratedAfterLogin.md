## Verdict

CONFIRMED. Session fixation vulnerability present. After successful password verification, the authenticated session is set without regenerating the session identifier. An attacker can plant a session ID before login and hijack it once the user authenticates.

## Source

File: `LoginHandler.php`, line 34

The vulnerability is in the login handler's failure to call `session_regenerate_id()` after password verification. The password is correctly verified with `password_verify()` (line 29), and timing-safe verification is applied to missing accounts (line 25). However, after successful authentication, the code directly sets `$_SESSION['user_id']` and `$_SESSION['authenticated']` without regenerating the session ID.

```php
// Line 29-35: Password verified, but session ID not regenerated
if (!password_verify($password, $user['password_hash'])) {
    return false;
}

// VULNERABLE: No session_regenerate_id() before setting authenticated state
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;
```

This allows a session fixation attack where an attacker can:
1. Obtain a session ID by visiting the login page
2. Trick or force the user to use that session ID
3. When the user logs in, the attacker's pre-existing session ID becomes authenticated

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
        session_regenerate_id(false);

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

The fix adds `session_regenerate_id(false)` on line 33, immediately after successful password verification and before authenticating the session. This forces PHP to create a new session ID and invalidate the old one, breaking any session fixation attack.

The `false` parameter (the default) preserves the old session data during the transition, which allows existing session variables to be carried forward if needed, while still invalidating the old ID. Per PHP security guidance, this is preferred because it allows detection and prevention of session hijacking attempts by comparing old and new session data timestamps.

The fix preserves all existing authentication logic (proper `password_verify()` use, timing-safe dummy hash on user lookup miss) and only adds the missing session regeneration step. The sink contract—setting authenticated session state—is satisfied with the addition of proper session ID rotation.

## Behaviour changes

- **Session ID invalidation**: The old session ID is invalidated after login. Any existing session cookies or URLs containing the old ID will no longer be valid.
- **Session data preservation**: Existing session data is preserved during regeneration (due to `false` parameter), so any application-specific session variables set before login remain accessible.
- **Authentication timing**: No change to authentication timing or password verification behavior. Dummy hash verification still executes on user-miss to prevent timing attacks.
- **Hijacking prevention**: Session fixation attacks are now prevented. Pre-authenticated session IDs cannot be escalated to authenticated sessions.
