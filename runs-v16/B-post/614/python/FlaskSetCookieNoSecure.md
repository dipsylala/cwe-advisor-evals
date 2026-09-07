## Verdict

Exploitable. The session token is sensitive authentication data and must not be transmitted over unencrypted HTTP. The `Secure` flag is mandatory to prevent interception.

## Source

Line 19: `token = issue_session_token(username)` produces a session token tied to the authenticated user.

## Fix

**Vulnerable code (line 22):**
```python
response.set_cookie("session_token", token, httponly=True)
```

**Fixed code:**
```python
response.set_cookie("session_token", token, httponly=True, secure=True, samesite='Lax')
```

## Explanation

The fix adds two security flags to the cookie. The `secure=True` parameter ensures the cookie is only transmitted over HTTPS connections, preventing interception on unencrypted links. The `samesite='Lax'` parameter mitigates CSRF attacks by restricting when the browser includes the cookie in cross-site requests. The existing `httponly=True` prevents JavaScript access, protecting against XSS-based cookie theft. Together, these flags align the cookie with industry best practices for sensitive authentication data. The fix assumes HTTPS is enforced site-wide; if HTTP is still reachable, the server must redirect all requests to HTTPS to make the `Secure` flag effective.

## Behaviour changes

- **Added `secure=True`**: Cookies are now sent only over HTTPS. Attempting to send the cookie over HTTP causes the browser to discard it, preventing unencrypted transmission. This is the required fix and has no downside for correctly deployed HTTPS.
- **Added `samesite='Lax'`**: Cookies sent in top-level navigations (following a link, form submission on same site) are included; cookies in cross-site requests like third-party iframes or fetch are omitted. This prevents CSRF attacks but may affect legitimate cross-site flows if the application relies on cookies in all cross-site contexts. For a login/session flow, `Lax` is the appropriate choice.
