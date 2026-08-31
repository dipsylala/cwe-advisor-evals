## Verdict

Confirmed. The `auth_user` cookie is set with the `secure` flag explicitly disabled, so it can be transmitted over plain HTTP even when the site is served over HTTPS, exposing the session-identifying value to interception on an unencrypted channel or via protocol-downgrade/mixed-content scenarios.

## Source

`e:/Github/cwe-advisor/evals/cases/614/php/SetcookieMissingSecure/SetcookieMissingSecure.php`, line 25:

```php
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

The sixth positional argument to `setcookie()` is the `secure` flag, and it is passed as `false`.

## Fix

```php
<?php

session_start();

function verifyCredentials(string $username, string $password): bool
{
    // Placeholder: real implementation checks a hashed password store.
    return $username !== '' && $password !== '';
}

function login(): void
{
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (!verifyCredentials($username, $password)) {
        http_response_code(401);
        echo 'Invalid credentials';
        return;
    }

    $_SESSION['user'] = $username;

    setcookie('auth_user', $username, [
        'expires'  => time() + 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    header('Location: /account');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    login();
}
```

## Explanation

The fix flips the `secure` attribute to `true` so the browser will only ever send `auth_user` back over an HTTPS connection, closing off the plaintext-interception path that CWE-614 flags. It is switched over to the PHP 7.3+ options-array form of `setcookie()` rather than just changing the sixth positional argument in place, because the array form is self-documenting (each flag is named instead of being a bare `true`/`false` in a fixed position that is easy to miscount) and it lets `SameSite` be set alongside `Secure` and `HttpOnly` in the same call, which is good practice for an authentication cookie carrying a username. `HttpOnly` was already `true` in the original code and is preserved. `SameSite=Lax` is a reasonable default that still allows normal top-level navigation (e.g. following a link into the app) while blocking the cookie from being sent on most cross-site requests; if this cookie is only ever needed for same-site requests, `Strict` could be used instead. No other behavior changes: the cookie name, value, expiry, and path are unchanged.
