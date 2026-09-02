## Verdict

exploitable (confidence: high)

CWE-614 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
Location: `SetcookieMissingSecure.php`, line 25

## Source

`$_SESSION['user']` is populated with the verified `$username` at line 22, immediately after `verifyCredentials()` succeeds in `login()`. That same username is written into the `auth_user` cookie at line 25. This is not a tainted-input trace - the cookie carries a server-asserted authentication value (the identity of the just-authenticated user), so its exposure comes from the missing transport-security attribute at the sink, not from an untrusted source.

## Fix

**Vulnerable code** (line 25):

```php
// SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
setcookie('auth_user', $username, time() + 3600, '/', '', false, true);
```

The 6th positional argument (`secure`) is explicitly `false`, so the browser will attach `auth_user` to plain-HTTP requests to the same host as well as HTTPS ones, exposing the authentication cookie to network interception.

**Fixed code**:

```php
setcookie('auth_user', $username, [
    'expires'  => time() + 3600,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
```

## Explanation

The call is converted from the 7-argument positional form to the PHP 7.3+ options-array form so `secure` and `samesite` can both be set explicitly. `secure` is flipped from `false` to `true`, which is the direct fix for the reported weakness: it stops the browser from sending `auth_user` over unencrypted HTTP. `httponly` stays `true`, unchanged from the original. `samesite` is added as `Strict`, per the PHP-specific guidance's instruction to combine `secure` with `httponly` and `samesite` as defence-in-depth for authentication cookies; `Strict` is appropriate here because the cookie is set immediately after a same-site form POST and the following redirect (`/account`) is same-site, so there is no inbound-link or OAuth-callback flow that `Strict` would break. This fix assumes the deployment already enforces HTTPS site-wide (the `Secure` flag has no protective effect otherwise) and does not address `session_start()` on line 3, which runs without `session_set_cookie_params()`/`session.cookie_secure` and so still issues `PHPSESSID` without the `Secure` flag - that is a distinct sink from the one reported at line 25 and is out of scope for this finding, but should be reviewed separately since it carries the same session-hijacking risk.

## Behaviour changes

- `secure`: `false` -> `true`. This is the fix itself - closes the reported weakness by withholding the cookie from HTTP requests.
- `samesite`: unset (browser default, effectively `Lax` on modern browsers) -> `'Strict'`. Not required to close CWE-614 itself, but added per the loaded PHP guidance's defence-in-depth recommendation for authentication cookies. Assumption: no cross-site entry point (SSO/OAuth redirect, inbound link that must carry the session) depends on this cookie being sent on a cross-site navigation; if one exists, use `'Lax'` instead.
- `httponly`: unchanged (`true` in both positional and array form).
- `expires`, `path`, `domain`: unchanged values, only re-expressed as array keys instead of positional arguments (required syntactically to reach the `secure`/`samesite` options).
