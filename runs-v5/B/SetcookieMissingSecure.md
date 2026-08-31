## Verdict

- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **Location**: `SetcookieMissingSecure.php`, line 25
- **Verdict**: exploitable
- **Confidence**: high
- **Assumptions**: Language inferred from file extension (`.php`) and syntax; no ambiguity to resolve.

## Source

- **Source**: `$_POST['username']`, read in `login()` and passed through `verifyCredentials()` (which only checks for a non-empty string, not a sanitizer relevant to cookie transport) before being assigned to `$_SESSION['user']` and used as the value of the `auth_user` cookie.
- **Sink**: `setcookie('auth_user', $username, time() + 3600, '/', '', false, true);` at line 25. This is the 7-argument positional form of `setcookie()`: name, value, expires, path, domain, `secure`, `httponly`. The `secure` argument (6th position) is explicitly passed `false`, so the cookie carrying the authenticated username is sent over both HTTP and HTTPS. `httponly` (7th position) is already `true`.
- The call chain is fully contained in this one file: request dispatch (`REQUEST_METHOD === 'POST'`) -> `login()` -> `setcookie()`. Nothing between the source and the sink constrains or overrides the `secure` value, so the path is live as reported.

## Fix

No third-party library is involved; this is a built-in PHP function, so no library/version recommendation applies.

**Vulnerable code:**

```php
// SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

**Fixed code:**

```php
// Options-array form (PHP 7.3+): secure flag set, httponly preserved, samesite added for defence-in-depth.
setcookie('auth_user', $username, [
    'expires'  => time() + 3600,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
```

## Explanation

The fix replaces the 7-argument positional call with the PHP 7.3+ options-array form and sets `'secure' => true`, so the browser will only transmit `auth_user` over an HTTPS connection, closing the interception path the finding reports. `httponly` is carried over unchanged (it was already `true` in the original call, so no behavioural change there), and `samesite => 'Strict'` is added per the language guidance's standard bundling of `secure`/`httponly`/`samesite` for a sensitive cookie set this way. `path` and `expires` are preserved exactly as in the original call; `domain` is omitted from the options array, which matches the original empty-string domain argument (both mean "default to the current host"). This fix only addresses the `auth_user` cookie set at line 25; the `PHPSESSID` cookie issued by the `session_start()` call on line 3 is a separate cookie whose `secure` flag depends on `session.cookie_secure` in `php.ini` (not visible in this file) and is outside the scope of this finding.

## Behaviour changes

- `secure`: `false` -> `true`. This is the fix itself - the cookie is now sent only over HTTPS. If any client legitimately depended on receiving this cookie over plain HTTP, that path breaks; this is the intended effect of the remediation and HTTPS should already be enforced site-wide.
- `samesite`: unset (PHP/browser default) -> `Strict`. New attribute not present in the original call. This is not required to close the reported `secure`-flag finding by itself, but is the language guidance's prescribed bundling for a sensitive cookie set via the options-array form. Effect: the browser will withhold `auth_user` on cross-site navigations (e.g. an external link into `/account`, or a cross-site POST), which it previously would have sent. If `auth_user` needs to be readable on cross-site top-level navigations, `Lax` is the safer choice instead of `Strict` - confirm the flow before deploying.
- `httponly`: `true` -> `true`. No change; carried over from the original positional argument.
- `path`, `expires`: unchanged.
- `domain`: empty-string positional argument -> omitted from the options array. No behavioural change; both mean "use the default (current) host".
