## Verdict

Exploitable. Session fixation vulnerability present.

## Source

Email and password parameters from `handle()` method. After `password_verify()` confirms the password is correct at line 29, the authenticated user ID is taken from the database result (`$user['id']`) and written directly to the session at line 34 without regenerating the session identifier.

## Fix

Vulnerable code (lines 29-35):
```php
        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['authenticated'] = true;
```

Fixed code:
```php
        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        // Regenerate session ID after successful authentication to prevent session fixation
        session_regenerate_id();

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['authenticated'] = true;
```

## Explanation

The fix calls `session_regenerate_id()` immediately after password verification succeeds and before setting the authenticated user ID in the session. This invalidates any pre-authentication session identifier the attacker may have planted, preventing session fixation. The session ID is regenerated with a fresh cryptographically-random value bound to the authenticated user, so an attacker cannot reuse a known session ID to hijack the login. The `$delete_old_session` parameter is left at its `false` default per the PHP guidance, which allows the framework to detect and log hijack attempts and avoids race conditions during session cleanup.

## Behaviour changes

None. `session_regenerate_id()` with the default `$delete_old_session = false` preserves the old session data while issuing a new session ID, maintaining the same contract as before (the session is still available and populated with the user ID immediately after the call). The new session ID is transparent to the caller—`$_SESSION` continues to work normally, and existing session cookie handling is unchanged.
