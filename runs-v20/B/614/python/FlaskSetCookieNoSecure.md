## Verdict

exploitable

- **cwe_id**: CWE-614
- **location**: `FlaskSetCookieNoSecure.py`, line 22 (`response.set_cookie("session_token", token, httponly=True)`)
- **confidence**: high

## Source

The session cookie value originates from `issue_session_token(username)` (line 19), called immediately after `authenticate()` succeeds in the `/login` view. The `username` feeding it comes from `request.form["username"]` (line 13), attacker-supplied POST data, but the cookie's sensitivity does not depend on that: it is a session-identifying credential (`"sess-" + username`) regardless of how the token is generated. It flows straight into `response.set_cookie(...)` at line 22 with no intervening transformation - a two-line, single-function data flow with no branching or validation to trace.

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
    response.set_cookie("session_token", token, httponly=True, secure=True)
    return response


def authenticate(username, password):
    return username == "admin" and password == "changeme"
```

## Explanation

The only change is adding `secure=True` to the `response.set_cookie()` call that issues the session cookie. Flask's `set_cookie()` defaults `secure` to `False`, so the cookie was previously sent over both HTTP and HTTPS; a network attacker positioned to observe or downgrade a connection could capture the session token and hijack the authenticated session. With `secure=True`, the browser withholds the cookie from any plain-HTTP request, closing that interception path while leaving every other attribute (name, value, `httponly=True`) unchanged. This is a per-cookie flag on `set_cookie()`, not a Flask app-wide session setting (`SESSION_COOKIE_SECURE`), because this route builds its cookie manually via `make_response()`/`set_cookie()` rather than through Flask's built-in session object.

## Behaviour changes

- **Added `secure=True` argument to `set_cookie()`**: this is the fix itself, not a side effect. Its only externally visible effect is that the browser will no longer transmit or store this cookie over an unencrypted HTTP connection - the intended remediation.
- No other arguments, return values, control flow, or response content were altered. `httponly=True` is unchanged; no `samesite` value was added since the original code did not set one and adding it is a separate, unraised concern.
- **verification**: compiled the fixed file with `python -m py_compile` (CPython 3.13) from a scratch copy outside the case directory - compiled cleanly, no diagnostics. `set_cookie`'s `secure` keyword is part of Flask/Werkzeug's `Response.set_cookie()` signature (used elsewhere in the same guidance's Key Principles and Taint Sinks entries for this CWE/language), so no unverified name was introduced.
- **assumptions**: none - the finding, source, and sink were unambiguous and the language-specific guidance directly names `secure=True` as the fix for this exact sink.
