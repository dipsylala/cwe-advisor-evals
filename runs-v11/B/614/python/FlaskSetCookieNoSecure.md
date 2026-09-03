## Verdict

Real issue - sensitive session cookie is transmitted without the `Secure` flag, allowing interception over HTTP connections.

## Source

```python
response.set_cookie("session_token", token, httponly=True)
```

Line 22 in FlaskSetCookieNoSecure.py. The `set_cookie()` call sets a session authentication token without the `secure=True` parameter.

## Fix

```python
response.set_cookie("session_token", token, httponly=True, secure=True, samesite='Lax')
```

Add `secure=True` to enforce HTTPS-only transmission. Add `samesite='Lax'` for CSRF protection on same-site cookie submission during form submissions and same-site redirects, which is appropriate for session cookies in typical web applications.

## Explanation

The `secure=True` flag ensures the browser only transmits the cookie over HTTPS connections. Without it, the cookie is sent over any connection (including unencrypted HTTP), exposing the session token to interception via man-in-the-middle attack or network sniffing. This is mandatory for cookies containing authentication or session data.

The additional `samesite='Lax'` parameter provides defence-in-depth by restricting when the cookie is sent on cross-site requests, mitigating CSRF attacks while still permitting the cookie on inbound navigations from external links (which is typically required for normal application flow).

## Behaviour changes

- Cookies are now sent only over HTTPS; browsers will not transmit them over HTTP
- Cross-site requests that do not come from top-level navigations will not include the cookie, reducing CSRF risk
- If the application runs over HTTP (e.g., during development), the cookie will not be set or transmitted; ensure HTTPS is enforced in production
- Session management will continue to work identically over HTTPS
