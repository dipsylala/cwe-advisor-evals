## Verdict

- **cwe_id**: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
- **location**: `FlaskSetCookieNoSecure.py`, line 22
- **verdict**: exploitable
- **confidence**: high

## Source

`issue_session_token(username)` (line 19, defined line 6-8) generates the session token that authenticates the user for subsequent requests. That value flows directly into `response.set_cookie("session_token", token, httponly=True)` at line 22 with no intervening validation or transformation - a direct, unbroken path from a sensitive credential to the cookie sink.

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

`response.set_cookie()` for Flask's `Response` object omits the `Secure` attribute unless `secure=True` is passed explicitly - the parameter defaults to `False`. Without it, the browser will send the `session_token` cookie over a plaintext HTTP connection if one is ever available (a downgrade, a stray `http://` link, mixed-content redirect, etc.), letting a network attacker capture the session token and hijack the authenticated session. Adding `secure=True` instructs the browser to withhold the cookie from any non-HTTPS request, closing that exposure. This is a code-level fix only; per the loaded guidance it still depends on HTTPS being enforced site-wide (e.g. an HTTP-to-HTTPS redirect and HSTS at the web server or a `Flask-Talisman`-style middleware) since the `Secure` flag has no effect if the site is reachable over plain HTTP in the first place - that infrastructure-level enforcement is outside this file and was not verified.

## Behaviour changes

- Added `secure=True` to the `set_cookie()` call. This is the flag being closed and is the only functional change - `httponly=True` is preserved unchanged, and no other argument, return value, or code path was altered.
- The knowledge base also recommends pairing `Secure` with a `SameSite` setting (`Strict`/`Lax`) as defense-in-depth, but that addresses CSRF exposure, a different weakness from the reported CWE-614 finding, so it was left out of this fix to keep the change scoped to the reported issue. Flagged here as a candidate for a separate finding/fix rather than folded silently into this one.
- **assumptions**: none - the file is small enough that the full source-to-sink path was directly visible with no ambiguity in language, sink, or exploitability.
