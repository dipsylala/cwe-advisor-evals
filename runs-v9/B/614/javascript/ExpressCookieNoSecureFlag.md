## Verdict

Exploitable. `res.cookie('auth_token', ...)` at line 15 sets an authentication token cookie without the `secure` attribute, so a browser will also transmit it over a plaintext HTTP connection to the same host, exposing the token to network interception.

## Source

`req.query.token` (line 8) - the signed session token the SSO provider hands back as a query parameter on the callback redirect. It is read directly into `authToken` and, after only a presence check, passed unmodified into the cookie value.

## Fix

Vulnerable code:

```javascript
router.get('/sso/callback', (req, res) => {
  const authToken = req.query.token;

  if (!authToken) {
    return res.status(400).send('Missing token');
  }

  // VULNERABLE: cookie carries the auth token but has no 'secure' attribute,
  // so the browser will also send it over plain HTTP.
  res.cookie('auth_token', authToken, {
    httpOnly: true,
    maxAge: 86400000,
  });

  res.redirect('/dashboard');
});
```

Fixed code:

```javascript
router.get('/sso/callback', (req, res) => {
  const authToken = req.query.token;

  if (!authToken) {
    return res.status(400).send('Missing token');
  }

  res.cookie('auth_token', authToken, {
    httpOnly: true,
    secure: true,
    maxAge: 86400000,
  });

  res.redirect('/dashboard');
});
```

## Explanation

The sink, `res.cookie()`, builds a `Set-Cookie` header from its options object; any attribute not present in that object is simply omitted from the header, so the missing `secure` key meant the cookie was valid on both HTTP and HTTPS. Adding `secure: true` makes Express append the `Secure` attribute, so the browser withholds `auth_token` from any plaintext HTTP request to the same host, closing the interception path while leaving the token's value, name, `httpOnly` protection, and 24-hour `maxAge` unchanged.

## Behaviour changes

- Added `secure: true` to the cookie options. Effect: the browser will no longer attach `auth_token` to requests made over plain HTTP to this host; if any part of the deployment still serves this route or `/dashboard` over HTTP (rather than HTTPS-only, as a session-token cookie requires), the cookie will silently stop being sent there and the user will appear logged out. This is the intended remediation, not incidental scope creep - confirm the site is served over HTTPS end-to-end (including that Express sees the connection as secure if TLS is terminated at a proxy) before deploying.
- No other options, arguments, return values, or control flow were changed. `sameSite` was left unset (Express's default of `Lax`); the loaded guidance flags `Strict` as unsafe here without confirming inbound-link/redirect behavior for this callback route, and adding it was out of scope for this CWE-614 finding.

### Assumptions

- Language/runtime confirmed as Node.js/Express from `require('express')` and `res.cookie()`.
- No SAST-provided call-path text was supplied beyond the file/line, so the source-to-sink trace was performed by direct code reading (Step 4, Option B) rather than an attached taint trace.
