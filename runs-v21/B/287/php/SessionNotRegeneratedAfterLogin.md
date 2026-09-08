## Verdict

Exploitable. The code verifies the password correctly with `password_verify()` at line 29, but then sets authenticated session variables without regenerating the session ID. An attacker can plant a known session cookie before the user logs in. If the user authenticates with that pre-existing session ID, the attacker's planted ID becomes authenticated and can be reused to impersonate the user.

## Source

Credential validation: `password_verify($password, $user['password_hash'])` at line 29 returns true, indicating successful authentication.

## Sink

Session state mutation at lines 34-35:
```php
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;
```

The sink is the point at which the session transitions from unauthenticated to authenticated. The weakness is that this transition uses the same session ID the client had before login, allowing session fixation.

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

        // Regenerate the session identifier after successful authentication
        // to prevent session fixation attacks.
        session_regenerate_id();
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

After a successful password verification, the code now calls `session_regenerate_id()` before setting the authenticated session variables. This invalidates the old session ID and issues a new one to the client, breaking the session fixation attack: any attacker-planted session ID from before login becomes invalid and cannot be used after authentication succeeds. The old session data is discarded by default (the `$delete_old_session` parameter is left at `false`), which is safe and recommended by PHP documentation to allow detection of session hijack attempts through access to the old ID.

## Behaviour changes

One added statement: `session_regenerate_id();` at line 33. This call generates a fresh session ID and invalidates the old one, which is required to prevent session fixation. The call:

- **Returns**: `true` on success (return value is not captured because no error handling is needed - regeneration failures are rare and fatal to the login flow; if it fails, the exception will terminate the script)
- **Arguments left implicit**: `$delete_old_session` defaults to `false`, which preserves the old session data for hijack detection and avoids race conditions that could be exploited if the old session were immediately deleted
- **Side effect**: Issues a new session cookie to the client and invalidates the previous one
- **No other contract changes**: The function still returns `true` on success and `false` on credential failure; password verification logic is unchanged; the session state variables are set identically

The fix preserves the existing security hardening (timing-safe password verification, dummy-hash verification on missing users) and adds the session-fixation defence without altering any other control flow or return behaviour.
