## Verdict

exploitable

## Source

`$username` at `login()` line 13 — `$_POST['username'] ?? ''`, attacker-controlled request input (also written into `$_SESSION['user']` at line 22, but the finding concerns the cookie set from it, not the session variable).

## Fix

The vulnerable sink is the `setcookie()` call at line 25:

`setcookie('auth_user', $username, time() + 3600, '/', '', false, true);`

This is the 7-argument positional form: `name, value, expire, path, domain, secure, httponly`. The `secure` argument (position 6) is passed `false`, so the `auth_user` authentication cookie is issued without the `Secure` flag and can be transmitted over an unencrypted HTTP connection, exposing it to network interception. `httponly` (position 7) is already `true`; `samesite` has no positional slot and is left at the PHP default.

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
        'samesite' => 'Strict',
    ]);

    header('Location: /account');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    login();
}
```

## Explanation

The positional `setcookie()` call was replaced with the PHP 7.3+ options-array form so `secure` can be set to `true`, closing the CWE-614 finding: the `auth_user` cookie can now only be transmitted over HTTPS. `httponly` is preserved at `true` (unchanged from the original), and `samesite` is set to `Strict` per the loaded PHP guidance, which prescribes combining `secure`, `httponly`, and `samesite` on every sensitive cookie for defence-in-depth. `Strict` is appropriate here because this is a same-origin, form-POST login flow with no inbound cross-site link or OAuth/SSO callback that would need the cookie sent on a top-level cross-site navigation. `expires`, `path`, and `domain` carry forward the original values (`time() + 3600`, `'/'`, `''`) unchanged; `name` and `value` are unchanged. Verified with `php -l` against a copy of the file (see Verification).

## Behaviour changes

- `secure`: `false` -> `true`. This is the fix for the reported weakness; the cookie is no longer sent over plaintext HTTP.
- `samesite`: unset (PHP/php.ini default) -> `'Strict'`. Not required to close CWE-614 itself, but explicitly prescribed by the loaded PHP guidance ("Combine with `httponly` and `samesite` for defence-in-depth... choosing `Lax` or `Strict` per flow"). `Strict` is chosen because the login form is same-origin POST with no cross-site entry point that depends on the cookie; if this cookie must later be readable on an inbound cross-site link (e.g. a shared/SSO login redirect), `samesite` would need to be relaxed to `Lax` at that time.
- Argument form: 7-positional-argument call -> options-array call. This is a syntax change only — `name` and `value` are passed the same way, and `expires`, `path`, `domain`, `httponly` all carry the same values as before, now as named keys instead of positions. No behavioural difference beyond enabling `secure` and `samesite` to be set.
- Return value: `setcookie()`'s boolean return was discarded before and remains discarded after — no change.

## Verification

Ran `php -l` (PHP 8.5.8 CLI, reachable in the environment) against a copy of the fixed file at a scratch path outside the repository: `No syntax errors detected`. The options-array form of `setcookie()`'s third parameter, and the `secure`/`httponly`/`samesite` keys, are documented PHP 7.3+ signature elements confirmed against the loaded `cwe/614/php/INDEX.md` guidance, which names this exact syntax ("PHP 7.3+ syntax"); no new symbol, function, or import was introduced.
