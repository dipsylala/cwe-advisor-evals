## Verdict

Confirmed. The `auth_token` cookie set in `router.get('/sso/callback', ...)` carries a signed SSO session token but is issued without the `secure` attribute, so a browser will also send it over a plain HTTP connection to the same host. Anyone positioned on the network path (e.g. a coffee-shop Wi-Fi MITM, a misconfigured intermediary, or a stray HTTP link) can capture the token and hijack the session, even if the site is normally served over HTTPS.

## Source

`req.query.token` (the SSO provider's redirect query parameter) flows unchanged into the sink at line 15.

## Fix

```javascript
const express = require('express');
const router = express.Router();

// SSO provider redirects here after authentication, handing back a signed
// session token as a query parameter. We store it in a cookie so the
// browser presents it on subsequent requests.
router.get('/sso/callback', (req, res) => {
  const authToken = req.query.token;

  if (!authToken) {
    return res.status(400).send('Missing token');
  }

  res.cookie('auth_token', authToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 86400000,
  });

  res.redirect('/dashboard');
});

module.exports = router;
```

## Explanation

Adding `secure: true` to the cookie options instructs the browser to withhold the `auth_token` cookie on any request that is not sent over HTTPS, closing the plaintext-interception path that the finding flags. This is the direct, minimal fix for CWE-614 at this sink.

Two related notes:

- `secure: true` only has effect when the app is actually served behind HTTPS end-to-end. If this app sits behind a reverse proxy or load balancer that terminates TLS and forwards plain HTTP internally, also set `app.set('trust proxy', 1)` and ensure the proxy forwards `X-Forwarded-Proto`, otherwise Express/Connect may still treat the connection as insecure (or, conversely, the browser will correctly refuse to send the cookie back over the internal HTTP hop only if it was set with `secure` under an HTTPS-facing origin — the cookie itself is unaffected by the internal hop as long as the browser's connection to the public origin is HTTPS).
- `sameSite: 'lax'` was added alongside the fix as defense-in-depth against cross-site request delivery of this session cookie; it is not required to resolve CWE-614 itself but costs nothing here since the cookie is only needed for same-site navigation after SSO callback. If the flow legitimately requires the cookie to be sent from a cross-site context (e.g. an embedded iframe redirect), `sameSite: 'none'` is required instead, but that value only works in combination with `secure: true`, so keep both attributes set together.
