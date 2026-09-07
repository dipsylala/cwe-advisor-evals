## Verdict
exploitable

## Source
`token = issue_session_token(username)` at line 19 produces a session token; the token flows directly to the cookie-setting sink.

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
The session token is a sensitive authentication credential and must be protected from network interception. The fix adds `secure=True` to enforce transmission over HTTPS only—without this flag, Flask allows the cookie to be sent over unencrypted HTTP, exposing it to man-in-the-middle attacks. The `samesite='Lax'` parameter adds CSRF protection while still allowing the cookie to be sent on inbound navigational requests (e.g., SSO flows), unlike `Strict` which would block it. Together these attributes enforce the token's confidentiality and integrity in transit.

## Behaviour changes
- **secure=True**: Enforces that the cookie is only transmitted over HTTPS connections. When the browser receives this flag, it discards the cookie if the connection is not HTTPS. This is essential for protecting session tokens from network sniffing.
- **samesite='Lax'**: Mitigates CSRF attacks by withholding the cookie from cross-site requests initiated by other sites, while still allowing it in top-level navigational requests (links, form submissions from the user's browser). Reason: the Python guidance recommends setting `SameSite` alongside `Secure` for defense-in-depth; `Lax` is the preferred default for session tokens to allow SSO and OAuth flows.
