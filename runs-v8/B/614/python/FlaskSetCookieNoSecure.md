## Verdict

exploitable

## Source

Line 19: `token = issue_session_token(username)` creates a sensitive session identifier containing authentication data (`"sess-" + username`). The token is set as a cookie without the `secure=True` flag, allowing transmission over unencrypted HTTP.

## Fix

**Vulnerable code (line 22):**
```python
response.set_cookie("session_token", token, httponly=True)
```

**Fixed code:**
```python
response.set_cookie("session_token", token, httponly=True, secure=True)
```

## Explanation

The `secure=True` parameter ensures the cookie is only transmitted over HTTPS connections. Without it, the browser will send this sensitive session token over unencrypted HTTP, exposing it to interception by network attackers or man-in-the-middle proxies. Setting `secure=True` enforces transport-layer confidentiality for this authentication cookie by preventing the browser from sending it on plaintext connections.

## Behaviour changes

- `secure=True` is added: The cookie will now only be transmitted over HTTPS connections. On HTTP requests, the browser will not send this cookie. This requires HTTPS to be enforced site-wide for the application; otherwise legitimate clients cannot authenticate.
