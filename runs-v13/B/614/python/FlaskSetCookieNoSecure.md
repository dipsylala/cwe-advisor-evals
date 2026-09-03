## Verdict

exploitable

## Source

The session token is generated from user-supplied username via `issue_session_token(username)` on line 19. The token variable is passed directly to the vulnerable sink without intermediate validation that would close the CWE-614 weakness.

## Fix

**Vulnerable code (line 22):**
```python
response.set_cookie("session_token", token, httponly=True)
```

**Fixed code:**
```python
response.set_cookie("session_token", token, httponly=True, secure=True, samesite="Lax")
```

## Explanation

The original code sets a session cookie without the `Secure` flag, allowing it to be transmitted over unencrypted HTTP connections where attackers can intercept it. The fix adds `secure=True` to enforce transmission only over HTTPS. The additional `samesite="Lax"` parameter provides CSRF protection by restricting cookie transmission on cross-origin requests. Together these attributes ensure the sensitive session token is protected both in transit (HTTPS-only) and against cross-site request forgery attacks.

## Behaviour changes

- **secure=True**: Cookies will now only be transmitted when the connection uses HTTPS. If the application still allows HTTP connections, authenticated users will not receive their session cookie on those connections and will appear logged out. This requires application-level enforcement of HTTPS (HTTP-to-HTTPS redirects or HSTS header) to avoid breaking login flows.
- **samesite="Lax"**: Restricts cookie transmission in cross-site requests. The cookie is sent in top-level navigations (e.g., user clicks a link to your site) but not in cross-origin forms or embedded resources. This prevents CSRF attacks while maintaining usability for normal browsing and SSO flows. Unlike `samesite="Strict"`, which withholds the cookie from inbound links, `"Lax"` allows the cookie on initial navigation, so legitimate workflows are preserved.
