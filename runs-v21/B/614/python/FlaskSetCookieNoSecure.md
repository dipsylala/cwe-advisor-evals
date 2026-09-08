## Verdict

The vulnerability is confirmed. The session cookie on line 22 lacks the `Secure` flag, allowing it to be transmitted over unencrypted HTTP connections and exposing the session token to interception.

## Source

File: FlaskSetCookieNoSecure.py, line 22

```python
response.set_cookie("session_token", token, httponly=True)
```

The call to `response.set_cookie()` sets a sensitive session authentication token but omits the `secure=True` parameter required to enforce HTTPS-only transmission.

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
    # SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
    response.set_cookie("session_token", token, httponly=True, secure=True, samesite='Strict')
    return response


def authenticate(username, password):
    return username == "admin" and password == "changeme"
```

## Explanation

The fix adds two parameters to the `set_cookie()` call:

- `secure=True`: Instructs the browser to transmit this cookie only over HTTPS connections, preventing the cookie from being sent over unencrypted HTTP. This is the primary mitigation for CWE-614.
- `samesite='Strict'`: Prevents the cookie from being sent in cross-site requests, defending against CSRF attacks. This is defense-in-depth; Strict mode withholds the cookie from inbound links and redirects, which is appropriate for a sensitive session identifier.

The `httponly=True` flag was already present and correctly prevents JavaScript from accessing the cookie via `document.cookie`.

## Behaviour changes

The application will now enforce HTTPS for the session cookie:
- Compliant browsers will refuse to transmit the session cookie over HTTP connections
- Session establishment will fail if the application is accessed via HTTP instead of HTTPS
- The application must enforce HTTPS site-wide (via a reverse proxy or middleware) for this flag to be effective
- The session cookie is now also protected from CSRF attacks and JavaScript injection

