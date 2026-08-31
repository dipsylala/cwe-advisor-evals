## Verdict

CWE-614 confirmed. The session token cookie is set without the `secure` flag, allowing it to be transmitted over unencrypted HTTP connections and exposing the sensitive session identifier to network eavesdropping.

## Source

Line 22 in `FlaskSetCookieNoSecure.py`:
```python
response.set_cookie("session_token", token, httponly=True)
```

The `set_cookie()` call sets a session token cookie with `httponly=True` but omits `secure=True`. This permits the cookie to be sent over both HTTP and HTTPS, creating a window for credential theft via network sniffing or protocol downgrade attacks.

## Fix

Add the `secure=True` parameter to the `set_cookie()` call:

```python
response.set_cookie("session_token", token, httponly=True, secure=True)
```

## Explanation

Session tokens transmitted in cookies must be marked `secure` to restrict transmission to HTTPS connections only. The `secure` flag prevents the browser from sending the cookie over unencrypted HTTP, protecting the token from interception on untrusted networks. Combined with `httponly=True`, which prevents JavaScript access, this dual protection makes the session token resistant to both network eavesdropping and client-side script injection attacks. All sensitive cookies in an HTTPS application should carry both flags.
