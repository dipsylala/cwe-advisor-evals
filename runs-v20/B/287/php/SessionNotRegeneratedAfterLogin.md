## Verdict

Exploitable. Confidence: high.

- **cwe_id**: CWE-287 (Improper Authentication)
- **location**: `LoginHandler.php`, line 34 (`$_SESSION['user_id'] = $user['id'];`)

## Source

The pre-authentication session identifier: whatever session ID is already attached to the client's session cookie when `handle()` is invoked (started elsewhere in the application via `session_start()`, not shown in this file). If the application accepts a session ID supplied by the client before login - the default PHP behavior unless the session handler is hardened - an attacker can plant a known session ID on a victim (e.g. via a crafted link or by setting the cookie in a shared/kiosk context) before the victim authenticates.

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

        // Regenerate the session ID on successful login so a session
        // identifier set before authentication (e.g. planted by an
        // attacker) cannot be reused as an authenticated session.
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

The sink at line 34 promotes the current session to an authenticated one by writing `user_id` and `authenticated` into `$_SESSION` without first calling `session_regenerate_id()`. Because the session identifier itself never changes at the authentication boundary, any session ID that existed before login - including one an attacker set on a victim's browser ahead of time (session fixation) - becomes a valid, fully authenticated session the moment the victim logs in, letting the attacker reuse that same ID to access the victim's account. The fix inserts a single `session_regenerate_id()` call immediately after credential verification succeeds and before any session data is written, issuing a fresh session ID for the authenticated session while the old (pre-login) ID is left invalid for future use as the current one. `$delete_old_session` is left at its default `false`, per PHP's own guidance, to avoid introducing a race/hijack-detection gap from immediate old-session deletion; the old session's data is superseded by the new ID going forward. No other logic, return value, or control flow in `handle()` is changed.

## Behaviour changes

- Added one call, `session_regenerate_id()` (no arguments, so `$delete_old_session` uses its documented default of `false`), immediately before the two `$_SESSION` writes. This is the only difference from the original code. It changes the session ID issued to the client on successful login (a new cookie value is sent) but does not change `handle()`'s return value, the data written to `$_SESSION`, or the failure-path behavior (dummy-hash timing, early returns) in any way.
- No other behaviour changes.

## Verification

Ran `php -l` (PHP 8.5.8 CLI) against the fixed file copied to a scratch location outside the repository: "No syntax errors detected." `session_regenerate_id()` is a PHP core function (ext/session, always available) requiring no import; it was checked by name against the PHP manual as the function this CWE's PHP guidance (`cwe/287/php/INDEX.md`) names for this exact fix, and no other new symbols were introduced.

### Assumptions

- Assumed session handling (`session_start()`, session cookie configuration) lives elsewhere in the application and is out of scope for this file-level fix; `LoginHandler::handle()` is assumed to run within an already-started session, consistent with it reading/writing `$_SESSION` on the surrounding lines.
