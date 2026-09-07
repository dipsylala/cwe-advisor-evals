## Verdict

exploitable

## Source

**CWE-287: Improper Authentication**

**Location:** evals/cases/287/php/SessionNotRegeneratedAfterLogin/LoginHandler.php:34

**Data Flow:**
- Source: Attacker-controlled session ID, planted in the victim's browser before login
- Sink: `$_SESSION['user_id'] = $user['id']` on line 34, following successful password verification
- Vulnerability: The session ID is not regenerated after successful authentication, allowing a session fixation attack where an attacker's pre-planted session ID becomes authenticated

The password verification on line 29 correctly uses `password_verify()`, but the authenticated session is assigned to the same session ID that existed before login. An attacker can establish a session with a known ID, trick a victim into logging in under that ID, and then hijack the authenticated session using the same ID.

## Fix

**Vulnerable code (line 33-35):**
```php
// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;
```

**Fixed code:**
```php
// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
session_regenerate_id();
$_SESSION['user_id'] = $user['id'];
$_SESSION['authenticated'] = true;
```

## Explanation

The fix adds `session_regenerate_id()` immediately after password verification and before marking the session as authenticated. This PHP standard-library function discards the pre-authentication session ID and issues a new one, keeping the session data intact but breaking any link an attacker established to the old ID. The victim's browser receives the new ID in the response and continues with it; the attacker's pre-planted ID no longer corresponds to an authenticated session. `session_regenerate_id()` is called with its default parameter (`$delete_old_session = false`), which preserves the old session data for a short window to detect hijack attempts and avoid race conditions, as documented in PHP's own warning for the function.

## Behaviour changes

**Sink contract preserved:** The fix regenerates the session ID after a successful login and then sets the authenticated session variables, exactly as the root CWE-287 and PHP-specific guidance prescribe. The session data remains intact and accessible; only the ID changes.

**No other changes to method contract:** The `handle()` method still returns `true` on successful login, `false` otherwise. No new exceptions are thrown (session_regenerate_id() never fails unless headers are already sent, which would indicate a different bug in the caller). No new dependencies introduced—`session_regenerate_id()` is part of PHP's standard session extension, available in all PHP versions in active use.

**Verification:** PHP syntax checked with `php -l` on fixed code: no errors.

**Assumptions:** None. The fix is directly prescribed by CWE-287/php guidance line 17.
