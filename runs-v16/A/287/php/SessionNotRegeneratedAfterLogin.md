## Verdict

**CONFIRMED.** The code populates the `$_SESSION` array after successful authentication but does not regenerate the session ID. This allows session fixation attacks where an attacker pre-sets a known session cookie and waits for the user to authenticate, then hijacks the authenticated session using the same ID.

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

The vulnerability is that credentials are verified, but no session ID regeneration occurs before or immediately after setting authentication state.

## Fix

```php
if (!password_verify($password, $user['password_hash'])) {
    return false;
}

session_regenerate_id(true);
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;

return true;
```

Call `session_regenerate_id(true)` immediately after password verification succeeds and before setting authenticated session state. The `true` argument ensures the old session data is destroyed, preventing an attacker from retaining the pre-authentication session.

## Explanation

Session fixation attacks occur when an attacker tricks a user into authenticating with a session ID controlled by the attacker. If the application does not invalidate the old session ID and create a new one during login, the attacker's pre-set ID remains valid after authentication, giving the attacker access to the authenticated session.

`session_regenerate_id(true)` generates a new session ID and discards the old session data in a single call. This must happen immediately after successful credential verification, before any authentication state is written to `$_SESSION`, to ensure the new session ID becomes bound to the authenticated user. Calling it after setting `user_id` and `authenticated` is less optimal but still correct; the optimal placement is before any session data is modified.
