## Verdict

exploitable (confidence: high)

CWE-614 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute.

## Source

`login()` in `FlaskSetCookieNoSecure.py` (Flask route `POST /login`): after successful authentication, `issue_session_token(username)` produces a session identifier (`token`) that is placed in a response cookie.

## Sink

`response.set_cookie("session_token", token, httponly=True)` at line 22. The call sets `httponly=True` but omits `secure`, which defaults to `False` in Flask's `Response.set_cookie`. The cookie carries the session token, so it will be sent by the browser over a plain-HTTP connection as well as HTTPS, exposing it to interception (e.g. network sniffing, MITM) if the client ever reaches the site over HTTP or is downgraded to it.

## Fix

Vulnerable code:

```python
    token = issue_session_token(username)
    response = make_response("logged in")
    # SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
    response.set_cookie("session_token", token, httponly=True)
    return response
```

Fixed code:

```python
    token = issue_session_token(username)
    response = make_response("logged in")
    response.set_cookie("session_token", token, httponly=True, secure=True)
    return response
```

## Explanation

Adding `secure=True` to the `set_cookie` call instructs the browser to withhold the `session_token` cookie on any non-HTTPS request, closing the plaintext-transmission path that CWE-614 flags. This is a one-line, additive change at the exact sink identified by the finding: it does not alter what the cookie carries, its name, its `HttpOnly` protection, or any other response behavior. The fix assumes the application is served over HTTPS in production (per the CWE-614 guidance, the `Secure` flag requires HTTPS to be effective) - if HTTPS is not yet enforced site-wide, that is a separate, infrastructure-level prerequisite the deployment should also confirm.

## Behaviour changes

- Added `secure=True` to `response.set_cookie(...)`: the only functional change. The cookie will no longer be sent by the browser over unencrypted HTTP; over HTTPS, behavior is unchanged.
- No other arguments, return values, or control flow were altered. `httponly=True` is preserved as-is; `samesite` was left unset (matching the original code) since it is a separate hardening concern (CSRF-related) not covered by this CWE-614 finding.
