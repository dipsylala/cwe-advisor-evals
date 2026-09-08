## Verdict

The vulnerability is confirmed. The `setcookie()` call at line 25 sets the `secure` flag to `false`, allowing the authentication cookie to be transmitted over HTTP, which exposes it to network interception.

## Source

User-supplied username from `$_POST['username']` at line 13, verified against credentials at lines 16-20, then stored in session and transmitted via an insecure cookie.

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

    setcookie('auth_user', $username, [
        'expires' => time() + 3600,
        'path' => '/',
        'domain' => '',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);

    header('Location: /account');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    login();
}
```

## Explanation

The original code passed `false` as the 6th positional argument to `setcookie()`, explicitly disabling the `Secure` flag. This allows browsers to send the authentication cookie over unencrypted HTTP connections, exposing it to network interception attacks.

The fix uses PHP 7.3+ options-array syntax to set `'secure' => true`, ensuring the cookie transmits only over HTTPS. Additional hardening via `'httponly' => true` prevents JavaScript from accessing the cookie (mitigating XSS cookie theft) and `'samesite' => 'Strict'` restricts the cookie to same-site requests (mitigating CSRF). The expiry, path, and domain remain unchanged to preserve application behaviour.

## Behaviour changes

- The authentication cookie is now transmitted only over HTTPS; HTTP requests will not send it.
- The cookie becomes inaccessible to JavaScript (`httponly` flag).
- The cookie is withheld from cross-site requests (`samesite` flag).
- HTTPS must be enforced site-wide for the `Secure` flag to be effective; a site still accessible over HTTP will not transmit the cookie on HTTP connections, potentially breaking login flows if not redirected to HTTPS.
