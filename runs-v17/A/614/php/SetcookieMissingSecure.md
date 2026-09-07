## Verdict
CONFIRMED - The authentication cookie is set without the `secure` flag, allowing transmission over unencrypted HTTP connections even when HTTPS is available.

## Source
Line 25: `setcookie('auth_user', $username, time() + 3600, '/', '', false, true);`

The sixth parameter (secure flag) is explicitly set to `false`, which fails to restrict the cookie to HTTPS-only transmission.

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
The `setcookie()` function's sixth parameter controls the `Secure` attribute. Changing it from `false` to `true` ensures the browser transmits the cookie only over HTTPS connections, preventing interception over unencrypted HTTP. The seventh parameter (`HttpOnly = true`) is already correctly set to prevent JavaScript access.

When a server sends a Set-Cookie header with `Secure`, browsers will not send that cookie to the server unless the connection is over HTTPS. This is essential for authentication tokens and session cookies to prevent credential theft via network eavesdropping.
