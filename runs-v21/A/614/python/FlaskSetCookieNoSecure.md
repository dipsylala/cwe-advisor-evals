## Verdict

True positive. The session token cookie is set without the `secure=True` attribute, allowing it to be transmitted over unencrypted HTTP connections and exposing it to network-based interception.

## Source

Line 22 in `FlaskSetCookieNoSecure.py`: `response.set_cookie("session_token", token, httponly=True)`

The sensitive session token, produced by `issue_session_token()`, is stored in a cookie that can be transmitted over HTTP, violating the confidentiality of the session identifier.

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
    response.set_cookie("session_token", token, httponly=True, secure=True)
    return response


def authenticate(username, password):
    return username == "admin" and password == "changeme"
```

## Explanation

The fix adds `secure=True` to the `set_cookie()` call on line 22. This attribute ensures the cookie is transmitted only over HTTPS connections, preventing it from being sent over unencrypted HTTP and eliminating the window for network-based session token interception. The existing `httponly=True` attribute prevents JavaScript from accessing the cookie, and the `secure=True` attribute now ensures it is only sent on secure channels.
