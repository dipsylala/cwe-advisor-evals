## Verdict

Exploitable. The cookie containing sensitive authentication data is transmitted without the `Secure` flag, exposing it to interception over unencrypted HTTP connections.

## Source

`$_POST['username']` (line 13), attacker-controlled input from an HTML form submission.

## Fix

**Vulnerable code (line 25):**
```php
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

**Fixed code:**
```php
setcookie('auth_user', $username, time() + 3600, '/', '', true, true);
```

## Explanation

The `secure` parameter (6th argument to `setcookie()`) controls whether the cookie is sent only over HTTPS. Setting it to `true` ensures the authentication cookie is transmitted only on encrypted connections, preventing interception over HTTP. The fix changes this boolean flag from `false` to `true` while preserving all other cookie attributes: expiration, path, domain, and `httponly` remain unchanged. This closes the CWE-614 weakness by enforcing transport-layer protection for a sensitive authentication cookie.

## Behaviour changes

None. The fix changes only the `secure` parameter and does not alter the function's return value, the cookie's name, value, lifetime, path, domain, or `httponly` setting. The `setcookie()` call remains compatible with the existing code flow.
