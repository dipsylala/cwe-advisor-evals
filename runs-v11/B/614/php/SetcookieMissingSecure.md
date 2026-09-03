## Verdict

EXPLOITABLE. The authentication cookie is set with `secure=false`, permitting transmission over unencrypted HTTP. An attacker on the network path can intercept the cookie and forge sessions.

## Source

Line 25 in `SetcookieMissingSecure.php`:

```php
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

The cookie name `'auth_user'` and the subsequent storage of `$_SESSION['user']` indicate this is an authentication cookie. The 6th positional argument is `false`, which disables the `Secure` flag.

## Fix

Replace with:

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

The fixed code enables the `secure` flag, ensuring the cookie is transmitted only over HTTPS connections. It also adds `samesite=Strict` to prevent CSRF attacks against the session and modernizes to the options-array form (PHP 7.3+) for clarity and to avoid future argument-order mistakes.

The `httponly` flag was already set in the original; it remains in the fixed code to block JavaScript access, completing the defence-in-depth strategy for session cookies. `samesite=Strict` prevents the cookie from being sent on cross-site requests, protecting against CSRF.

## Behaviour changes

- The cookie is now rejected by the browser if transmitted over HTTP.
- The cookie is not sent on cross-site requests (due to `samesite=Strict`).
- JavaScript cannot access the cookie (unchanged; `httponly` was already present).
- HTTPS must be enforced site-wide for the cookie to function; if HTTP access is not redirected to HTTPS, the cookie will not be set and login will fail.
