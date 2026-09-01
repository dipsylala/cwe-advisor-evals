## Verdict

Exploitable. The authentication cookie `auth_user` is set with `secure=false`, permitting transmission over unencrypted HTTP despite carrying session data, exposing the token to network interception.

## Source

Username from `$_POST['username']` (line 13), verified through `verifyCredentials()` and assigned to `$_SESSION['user']` (line 22), then passed to the `setcookie()` sink (line 25).

## Fix

```php
setcookie('auth_user', $username, time() + 3600, '/', '', true, true);
```

Change the 6th parameter (`secure`) from `false` to `true`.

## Explanation

The `setcookie()` call at line 25 passes `false` as the `secure` parameter, instructing the browser to transmit the cookie over both HTTP and HTTPS. By changing this to `true`, the cookie is restricted to HTTPS-only transmission, preventing leakage over unencrypted HTTP channels. The cookie already carries authentication data (`$username`) and should never be exposed to network sniffing. The `httponly` flag (7th parameter) is already correctly set to `true`, providing additional XSS protection. This fix closes the weakness while preserving the existing cookie lifetime (3600 seconds), path, and HttpOnly protections.

## Behaviour changes

**Functional behaviour**: The cookie is now sent only over HTTPS connections. Sites not enforcing HTTPS will see login fail silently if the browser withholds the cookie; this is the correct behaviour and makes insecure deployments fail visibly rather than falling back to plaintext transmission.

**Testing required**: Verify that HTTPS is enforced site-wide. Confirm in a production-like environment that the cookie is not sent over HTTP (use browser DevTools Network tab or `curl -k https://...` vs. `curl http://...`).
