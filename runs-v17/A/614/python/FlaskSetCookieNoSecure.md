## Verdict
The finding is a true positive. The session token cookie is set without the `secure` attribute, allowing it to be transmitted over unencrypted HTTP connections.

## Source
**File:** FlaskSetCookieNoSecure.py  
**Line:** 22  
**Sink:** `response.set_cookie("session_token", token, httponly=True)`

The application sets a sensitive session token cookie without the `secure=True` flag. While `httponly=True` prevents JavaScript access, the `secure` attribute is required to restrict transmission to HTTPS connections only, protecting against man-in-the-middle attacks.

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
The fix adds `secure=True` to the `set_cookie()` call. This flag instructs browsers to send the cookie only over HTTPS connections, preventing transmission over unencrypted HTTP. Combined with `httponly=True`, this provides defense-in-depth: the `secure` attribute protects the cookie in transit against eavesdropping and MITM attacks, while `httponly` prevents JavaScript from accessing it locally. Both attributes are required for production session handling.
