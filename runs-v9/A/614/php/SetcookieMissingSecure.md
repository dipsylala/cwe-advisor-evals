## Verdict

Confirmed. The `auth_user` cookie is set without the `Secure` attribute, so a browser will also transmit it over a plain HTTP connection, exposing the session-identifying value to network-level interception or downgrade attacks.

## Source

`E:/Github/cwe-advisor/evals/cases/614/php/SetcookieMissingSecure/SetcookieMissingSecure.php`, line 25:

```php
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

The sixth positional argument (`secure`) is `false`, while the seventh (`httponly`) is already correctly set to `true`.

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

`setcookie()`'s sixth positional parameter controls the `Secure` attribute; it was hardcoded to `false`, so the `Set-Cookie` header carried no `Secure` flag and the cookie would be sent over unencrypted HTTP as well as HTTPS. Since `auth_user` is set right after establishing the authenticated session, an attacker positioned on the network path (open Wi-Fi, ARP spoofing, a forced HTTP downgrade) could capture it and reuse it to impersonate the user.

The fix switches to the PHP 7.3+ options-array form of `setcookie()` and sets `'secure' => true`, which adds the `Secure` attribute so the browser only ever sends the cookie over HTTPS. `'httponly' => true` is preserved from the original call to keep the cookie inaccessible to JavaScript (mitigating theft via XSS), and `'samesite' => 'Lax'` is added as defense-in-depth against cross-site request delivery of the cookie; neither of these changes narrows the original finding, which was specifically the missing `Secure` attribute.

Because the application already calls `session_start()` and stores the authenticated username in `$_SESSION['user']`, note that this separate `auth_user` cookie is redundant with the PHP session cookie for authentication purposes. If it exists only for the server to read the current username without a session lookup, consider whether it needs to carry the raw username at all, or whether it should be dropped in favor of relying on `$_SESSION` alone — but that is a design simplification, not a requirement for closing this finding, which is fully addressed by adding `Secure`.
