## Verdict

Confirmed. Session ID is not regenerated after successful authentication, allowing session fixation attacks where an attacker plants a session ID before login and hijacks that same session after the user authenticates.

## Source

**File:** LoginHandler.php, lines 29-35

```php
if (!password_verify($password, $user['password_hash'])) {
    return false;
}

// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;
```

The password is verified correctly with `password_verify()`, but the unauthenticated session ID persists into the authenticated session.

## Fix

Add `session_regenerate_id();` immediately after password verification and before setting authenticated session variables:

```php
if (!password_verify($password, $user['password_hash'])) {
    return false;
}

session_regenerate_id();
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;
```

## Explanation

Calling `session_regenerate_id()` creates a new session ID and invalidates the old one, preventing session fixation. An attacker who planted a session ID in the victim's browser before login will no longer have access to the authenticated session, because the ID changed at the authentication boundary. The `$delete_old_session` parameter is left at its default `false` to preserve the old session data for a brief period, which allows for proper cleanup and helps detect session hijack attempts via comparison of old and new session IDs.

## Behaviour changes

- **New behavior:** After a successful login, the session ID is regenerated and a new session cookie is issued to the client.
- **User impact:** Clients receive a new session cookie upon successful authentication; existing session state (e.g., CSRF tokens) must be re-established in the new session.
- **Security impact:** Session fixation attacks are eliminated; pre-authentication session IDs cannot be converted into authenticated sessions.
