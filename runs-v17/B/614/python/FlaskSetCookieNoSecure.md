## Verdict

Exploitable. The session token cookie is set without the `secure=True` flag, allowing it to be transmitted over unencrypted HTTP connections despite containing sensitive authentication data. An attacker on the network can intercept the session token in plaintext.

## Source

`issue_session_token(username)` at line 8 produces a session token that is sensitive authentication data: `"sess-" + username`.

## Sink

`response.set_cookie("session_token", token, httponly=True)` at line 22 sets the session token as a cookie without the `secure=True` flag, allowing transmission over HTTP.

## Fix

### File: FlaskSetCookieNoSecure.py

```python
from flask import Flask, request, make_response

app = Flask(__name__)


def issue_session_token(username):
    # In a real app this would be a signed, random session identifier.
    return "sess-" + username


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    if not authenticate(username, password):
        return "invalid credentials", 401

    token = issue_session_token(username)
    response = make_response("logged in")
    response.set_cookie("session_token", token, httponly=True, secure=True, samesite='Lax')
    return response


def authenticate(username, password):
    return username == "admin" and password == "changeme"
```

## Explanation

The fix adds two security attributes to the cookie:

1. `secure=True` - enforces HTTPS-only transmission, preventing the session token from being sent over unencrypted HTTP connections where network attackers could intercept it.

2. `samesite='Lax'` - provides defense in depth against CSRF attacks by restricting when the browser sends the cookie in cross-site requests. The 'Lax' setting allows the cookie in top-level navigations and same-site requests while blocking it in cross-site POST requests and embedded resources.

These attributes align with the CWE-614 remediation guidance and establish the secure-session pattern for sensitive authentication cookies in Flask.

## Behaviour changes

- **`secure=True` added**: The cookie will now only be transmitted over HTTPS connections. If the application is not configured to enforce HTTPS site-wide, this may prevent the session from working over HTTP. This is intentional and required - the fix requires HTTPS to be enabled in the deployment environment.
- **`samesite='Lax'` added**: The browser will now restrict the cookie's transmission in cross-site requests. This does not affect normal same-site navigation or legitimate inbound links to the login endpoint, but prevents accidental CSRF-based cookie injection from untrusted third-party sites.

No other behavior changes. The cookie name, value, and httponly flag remain unchanged.

**Verification**: Python syntax check (`python -m py_compile`) passed.

**Assumptions**: The application is or will be deployed with HTTPS enforcement enabled. The 'Lax' SameSite value was chosen as the recommended balance for login flows per the language-specific guidance; 'Strict' would prevent legitimate OAuth/SSO inbound callbacks. Both are more secure than omitting the attribute entirely.
