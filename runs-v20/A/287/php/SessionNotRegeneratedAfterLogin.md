## Verdict

Confirmed. `LoginHandler::handle()` authenticates the user and then writes the authenticated identity directly into the existing `$_SESSION` superglobal without first regenerating the session ID. Any session identifier the client held prior to authentication (attacker-fixated, or simply pre-existing) remains valid and becomes privileged after login, which is a session fixation flaw falling under CWE-287 (Improper Authentication).

## Source

`E:/Github/cwe-advisor/evals/cases/287/php/SessionNotRegeneratedAfterLogin/LoginHandler.php`, method `handle(string $email, string $password): bool`. The session write occurs at:

```
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;
```

This runs immediately after `password_verify()` succeeds, on the session that was active when the request arrived - there is no `session_regenerate_id()` call anywhere in the file, so the pre-login session ID is reused as the post-login (authenticated) session ID.

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

        // Regenerate the session ID before writing any authenticated state.
        // This discards whatever ID the client held before login (which may
        // have been fixated by an attacker) and issues a fresh one, deleting
        // the old session's data on the server so it cannot be replayed.
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

`session_regenerate_id(true)` asks PHP to generate a new session ID for the current session while keeping the existing session data available to copy forward, and the `true` argument tells it to delete the old session file on disk (or old session-store record) immediately rather than leaving it around. Calling it right after credentials are verified, but before any `$_SESSION` write, ensures:

- Any session ID that existed before authentication - whether it was handed to the victim by an attacker (session fixation) or was simply a stale anonymous session - is invalidated the moment the user proves their identity.
- The privileged keys (`user_id`, `authenticated`) are only ever associated with the newly issued ID, so an attacker who knows or fixated the pre-login ID gains nothing by the victim logging in.
- Passing `true` (delete old session) closes the window where the old ID could still be replayed against the server-side session store between regeneration and garbage collection.

No other behavior of `handle()` changes: the credential check, timing-safe dummy-hash comparison for unknown accounts, and return values are unchanged, so this is a minimal, targeted fix for the missing session regeneration.
