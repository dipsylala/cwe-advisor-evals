## Verdict
The vulnerability is confirmed. The authentication cookie is set without the `secure` attribute, which allows the browser to transmit it over unencrypted HTTP connections, exposing it to interception.

## Source
The vulnerable code at line 15 sets an authentication cookie without the `secure` flag:
```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});
```

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

  // SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
  res.cookie('auth_token', authToken, {
    httpOnly: true,
    secure: true,
    maxAge: 86400000,
  });

  res.redirect('/dashboard');
});

module.exports = router;
```

## Explanation
CWE-614 occurs when a sensitive cookie transmitted over HTTPS lacks the `Secure` attribute. This allows the browser to send the cookie over unencrypted HTTP, exposing it to network-level interception.

The fix adds `secure: true` to the cookie options. This forces the browser to only send the cookie when the connection is encrypted (HTTPS), preventing transmission over plain HTTP. Combined with the existing `httpOnly: true` flag, this provides defense-in-depth: the `Secure` attribute protects against network interception, and `httpOnly` prevents JavaScript-based cookie theft.
