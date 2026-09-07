# CWE-287: Improper Authentication - Session Not Regenerated After Login

## Verdict

Exploitable. The application validates the password correctly but fails to regenerate the session identifier after successful authentication. This enables session fixation attacks where an attacker can pre-plant a known session ID, trick the user into logging in with that ID still active, and then use the pre-planted ID to assume the authenticated session.

## Source

Email and password submitted by the user as parameters to the `handle()` method (line 16).

## Sink

Line 34: `$_SESSION['user_id'] = $user['id'];` - the session assignment occurs without first regenerating the session ID to invalidate any pre-authentication identifier.

## Fix

**Vulnerable code:**

```php
        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['authenticated'] = true;

        return true;
```

**Fixed code:**

```php
        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        session_regenerate_id();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['authenticated'] = true;

        return true;
```

## Explanation

After successful password verification, call `session_regenerate_id()` before storing the authenticated user ID in the session. This invalidates any session identifier an attacker may have pre-planted in the victim's browser, preventing session fixation. The call generates a new session ID while preserving all existing session data (using the default `$delete_old_session = false`), so the login handler's subsequent writes to `$_SESSION` apply to the fresh, authenticated session. The application's behaviour remains identical to the user except that the session now cannot have been hijacked via fixation before the login completed.

## Behaviour changes

None. `session_regenerate_id()` with default parameters generates a new session ID and preserves all session data already present, leaving the sink contract unchanged. The user receives the new session ID in the response cookie, and subsequent session operations use the regenerated ID. No return values change, no arguments differ, and no previously-discarded output is surfaced.
