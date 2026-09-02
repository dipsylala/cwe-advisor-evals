## Verdict

Confirmed. The session cookie is set without the `Secure` attribute, so a browser will also transmit it over a plain HTTP connection, exposing the session token to network eavesdroppers and active on-path attackers even when the site is normally served over HTTPS.

## Source

`login()` in `FlaskSetCookieNoSecure.py`, lines 12-23: after successful authentication, `issue_session_token(username)` produces a session identifier (`token`) that is then attached to the outgoing response as a cookie.

## Fix

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
    response.set_cookie(
        "session_token",
        token,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return response


def authenticate(username, password):
    return username == "admin" and password == "changeme"
```

Additionally, set `app.config["SESSION_COOKIE_SECURE"] = True` (and `SESSION_COOKIE_HTTPONLY = True`) if the application also uses Flask's built-in session cookie elsewhere, so the same protection applies consistently across all cookies the app issues, not just this one `set_cookie` call.

## Explanation

`Response.set_cookie()` defaults `secure` to `False`. Without `secure=True`, the browser will include the `session_token` cookie on any request to the same host regardless of scheme, including unencrypted `http://` requests. An attacker positioned on the network path (public Wi-Fi, a compromised router, DNS/ARP spoofing forcing a downgrade, or a stray HTTP link) can capture the cookie in transit and replay it to hijack the authenticated session.

Adding `secure=True` instructs the browser to withhold the cookie from any non-HTTPS request, closing that transmission channel. `httponly=True` was already present, which blocks client-side script access (mitigating cookie theft via XSS) but does nothing to prevent interception over an unencrypted connection - the two flags address different threats and are both needed. `samesite="Lax"` is included as defense-in-depth against cross-site request forgery riding on the session cookie; it does not by itself address the missing-`Secure` finding but is a low-cost addition when touching this call.

This fix only changes browser-side transmission behavior; it assumes the deployment already terminates TLS in front of this Flask app (e.g., via a reverse proxy or WSGI server configured for HTTPS). If the app is ever served directly over plain HTTP, `Secure` cookies will not be sent to the browser at all, so verify TLS termination is in place before deploying this change, and confirm in a browser or with `curl -v` that the `Set-Cookie` header for `session_token` includes `Secure` after the fix.
