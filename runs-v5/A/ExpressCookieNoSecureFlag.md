## Verdict

Confirmed. The cookie set at line 15 carries a signed SSO session token but omits `secure: true`, so the browser will also attach it over a plain HTTP connection, exposing the token to network-level interception or downgrade attacks.

## Source

`e:/Github/cwe-advisor/evals/cases/614/javascript/ExpressCookieNoSecureFlag/ExpressCookieNoSecureFlag.js`, `router.get('/sso/callback', ...)`: `authToken` comes from `req.query.token`, an SSO-provider-supplied session credential, and is written straight into a cookie with no `secure` attribute.

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

Adding `secure: true` to the cookie options instructs the browser to withhold `auth_token` from any request sent over plain HTTP, so the session credential is only ever transmitted on an encrypted TLS connection and cannot be captured by a network eavesdropper or a downgrade/mixed-content attack. This complements the existing `httpOnly: true` (which blocks script/XSS access) without removing it. `sameSite: 'lax'` is added as a low-cost adjacent hardening step so the token is not attached to unrelated cross-site navigations; it does not substitute for the `secure` fix, which is the direct remediation for the reported finding. If the application must also serve plain HTTP in non-production environments, gate `secure` on the deployment's TLS posture (e.g. `secure: req.secure` behind a trusted `trust proxy` setting, or an environment flag) rather than dropping the attribute, since silently omitting it in production reopens the same exposure.
