## Verdict

Exploitable. Line 25 sets a sensitive authentication cookie with the `secure` parameter explicitly set to `false`, allowing it to be transmitted over unencrypted HTTP connections.

## Source

`$_POST['username']` on line 13, untrusted user input from the POST request, passed to the authentication cookie via `setcookie()` on line 25.

## Fix

### File: SetcookieMissingSecure.php

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

    // SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
    setcookie('auth_user', $username, time() + 3600, '/', '', true, true);

    header('Location: /account');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    login();
}
```

## Explanation

The fix changes the `secure` parameter of `setcookie()` from `false` to `true` on line 25. This ensures the `auth_user` cookie is only transmitted over HTTPS connections, preventing interception over unencrypted HTTP. The `httponly` flag remains `true`, providing additional defense against client-side script access. The username value is still passed without further sanitization to the cookie, which is appropriate for a cookie value that will be transmitted securely and validated server-side on retrieval.

## Behaviour changes

The cookie will now only be transmitted when the connection is HTTPS. Any code path that previously relied on the cookie being sent over HTTP will no longer receive it on those connections. This is the intended security hardening and aligns with the production requirement that authentication cookies only travel over encrypted channels.
