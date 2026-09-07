## Verdict

CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute. Line 22 sets a session token cookie without the `secure=True` flag, allowing the browser to send the cookie over unencrypted HTTP connections.

## Source

```python
response.set_cookie("session_token", token, httponly=True)
```

## Fix

```python
response.set_cookie("session_token", token, httponly=True, secure=True)
```

## Explanation

Session tokens are sensitive credentials that authenticate a user. The `secure=True` flag instructs the browser to send the cookie only over HTTPS connections, preventing network interception of the token over unencrypted channels. Combined with `httponly=True` (which prevents JavaScript access), this implements defense-in-depth: `httponly` guards against JavaScript injection, while `secure` guards against network eavesdropping. Without `secure=True`, the browser will send the session token over any HTTP connection, exposing it to passive network attackers even when the application's login flow uses HTTPS.
