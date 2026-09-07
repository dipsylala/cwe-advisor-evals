## Verdict

Exploitable

## Source

`$_POST['username']` (line 13)

## Fix

**Vulnerable code (line 25):**
```php
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

**Fixed code:**
```php
setcookie('auth_user', $username, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

## Explanation

The authentication cookie is set with the `secure` flag set to `false`, allowing it to be transmitted over unencrypted HTTP connections. An attacker on the network can intercept the cookie and hijack the user's session. The fix sets `secure` to `true`, ensuring the cookie is only sent over HTTPS. The fix converts to the PHP 7.3+ options-array form to enable the `samesite` attribute, which provides additional CSRF protection by preventing the cookie from being sent in cross-site requests.

## Behaviour changes

- Requires PHP 7.3+ for the options-array form (positional form with `secure => true` works on earlier versions if needed)
- Adds `samesite: 'Strict'` cookie attribute, which prevents the cookie from being sent in any cross-site context (cross-site links, form submissions, or embedded requests) — this may affect legitimate cross-site workflows that depend on the cookie being included; verify compatibility with single sign-on (SSO) or OAuth flows if the application uses them
- Cookie will only be transmitted over HTTPS connections, making plaintext HTTP requests fail silently for authentication
