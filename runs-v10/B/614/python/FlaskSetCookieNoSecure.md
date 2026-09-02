## Verdict

**Confirmed exploitable.** The session cookie is set without the `Secure` flag, allowing it to be transmitted over unencrypted HTTP connections where it can be intercepted.

## Source

Line 22 in `login()`:
```python
response.set_cookie("session_token", token, httponly=True)
```

The `token` is a session identifier issued on line 19 by `issue_session_token(username)`. The sink is `response.set_cookie()`, which sets a cookie on the HTTP response without specifying `secure=True`.

## Fix

Add `secure=True` to the `set_cookie()` call:

```python
response.set_cookie("session_token", token, httponly=True, secure=True)
```

## Explanation

The `Secure` flag instructs the browser to transmit the cookie only over HTTPS connections, preventing it from being sent over unencrypted HTTP. Without this flag, an attacker on a network path between the client and server (or via HTTP fallback) can intercept the session token. The fix adds `secure=True` as a parameter to `response.set_cookie()`, enforcing HTTPS-only transmission for this sensitive session identifier. This aligns with Flask's cookie security best practices and the guidance in CWE-614.

## Behaviour changes

**Before fix:** The session cookie is transmitted over both HTTP and HTTPS connections.

**After fix:** The session cookie is transmitted only over HTTPS connections. If a client attempts to connect via HTTP, the browser will not include the cookie in the request, and the session will not be established unless the connection is upgraded to HTTPS.
