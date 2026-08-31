## Verdict

Confirmed exploitable. The authentication cookie is transmitted without the `Secure` flag, exposing it to interception over unencrypted HTTP connections.

## Source

Line 13-14: User input from `$_POST['username']` and `$_POST['password']` is verified via `verifyCredentials()`.

Line 22: The verified username is stored in `$_SESSION['user']`.

Line 25: The same username is set as an authentication cookie via `setcookie()` with the `secure` parameter explicitly set to `false`.

## Fix

**Vulnerable code (line 25):**
```php
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

**Fixed code:**
```php
setcookie('auth_user', $username, time() + 3600, '/', '', true, true);
```

Change the 6th parameter (the `secure` flag) from `false` to `true`.

## Explanation

The `setcookie()` function's 6th parameter controls the `Secure` flag on the cookie. When set to `false`, the cookie is transmitted over both HTTP and HTTPS connections, allowing attackers on the network to intercept the authentication credential. Setting it to `true` restricts transmission to HTTPS only, ensuring the cookie is never sent over unencrypted connections. This closes the CWE-614 vulnerability by enforcing transport-layer confidentiality for the sensitive authentication cookie.

## Behaviour changes

The authentication cookie will no longer be transmitted over HTTP connections. Any client attempting to access the application over unencrypted HTTP will not receive the `auth_user` cookie, ensuring it cannot be intercepted. This requires the application to be deployed with HTTPS as the primary access mechanism; pure HTTP access will fail to maintain the cookie-based session. This is the correct and intended behaviour for protecting authentication credentials.
