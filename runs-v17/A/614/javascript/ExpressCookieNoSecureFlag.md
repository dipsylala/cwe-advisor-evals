## Verdict
CONFIRMED. The `res.cookie()` call at line 15 sets a sensitive authentication token in a cookie without the `secure` flag, allowing it to be transmitted over unencrypted HTTP connections.

## Source
Line 15 in ExpressCookieNoSecureFlag.js: The `res.cookie()` call sets an authentication token (`authToken`) in a cookie named `auth_token`. The cookie configuration includes `httpOnly` to prevent JavaScript access and `maxAge` to set expiration, but omits the `secure` flag.

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
    maxAge: 86400000,
    secure: true,
  });

  res.redirect('/dashboard');
});

module.exports = router;
```

## Explanation
The fix adds `secure: true` to the cookie options. This flag restricts cookie transmission to HTTPS connections only, preventing the browser from sending the sensitive authentication token over unencrypted HTTP. Combined with the existing `httpOnly` flag, this provides defense-in-depth: `httpOnly` prevents JavaScript access and `secure` prevents interception over unencrypted channels. This is the standard Express.js pattern for protecting session and authentication cookies in production environments.
