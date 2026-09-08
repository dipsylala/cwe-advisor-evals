## Verdict

Confirmed. `res.cookie('auth_token', authToken, { httpOnly: true, maxAge: 86400000 })` sets a session-authentication cookie without the `secure` attribute. Express's `res.cookie()` defaults `secure` to `false`, so the browser will send this cookie over a plain-HTTP connection if one is ever made to the host (a downgraded link, a misconfigured proxy, mixed-content subresource, etc.), exposing the session token to network interception.

## Source

`req.query.token` (the SSO provider's redirected token) flows directly into the `res.cookie('auth_token', authToken, ...)` call at line 15 in `ExpressCookieNoSecureFlag.js`, which is the sink.

## Fix

### File: ExpressCookieNoSecureFlag.js
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
    sameSite: 'strict',
    maxAge: 86400000,
  });

  res.redirect('/dashboard');
});

module.exports = router;
```

## Explanation

Adding `secure: true` instructs the browser to withhold the `auth_token` cookie from any request that is not made over HTTPS, which is the direct remediation for CWE-614: it ensures a session-authentication token can never be transmitted in cleartext, even if the application or an intermediary later serves an HTTP endpoint on the same host. `httpOnly: true` was already present and is preserved unchanged.

`sameSite: 'strict'` is added as defense-in-depth alongside the required fix: since this cookie carries a bearer session token set from a redirect flow, restricting it to same-site requests reduces exposure to cross-site request forgery and token leakage via cross-site navigation, without weakening the primary fix. No other behavior of the handler changes: the token is still validated for presence, still stored under the same cookie name and `maxAge`, and the redirect target is unchanged, so this is a targeted attribute fix rather than a rework of the SSO callback logic.
