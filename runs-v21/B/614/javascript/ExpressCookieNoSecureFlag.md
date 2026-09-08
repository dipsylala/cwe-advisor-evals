## Verdict

Exploitable. The authentication token from the SSO provider is stored in a cookie without the `secure` flag, allowing it to be transmitted over unencrypted HTTP connections and exposed to man-in-the-middle attacks.

## Source

`req.query.token` - the authentication token parameter passed from the SSO provider callback (attacker-controllable through redirect).

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
    sameSite: 'lax',
  });

  res.redirect('/dashboard');
});

module.exports = router;
```

## Explanation

The cookie options now include `secure: true`, which enforces HTTPS-only transmission - the cookie is not sent over unencrypted HTTP connections, eliminating the attack surface for network sniffing and man-in-the-middle interception. The `sameSite: 'lax'` attribute was added to mitigate CSRF attacks while preserving the SSO callback flow, which requires the cookie to be sent with top-level navigations from the SSO provider's redirect. This combination closes CWE-614 while maintaining authentication functionality.

## Behaviour changes

- **Added `secure: true`**: Enforces HTTPS-only transmission. The cookie will not be sent over HTTP connections, requiring the application to run on HTTPS in production. This is a security requirement, not a regression.
- **Added `sameSite: 'lax'`**: Mitigates CSRF attacks by restricting cross-site cookie transmission, but allows top-level navigations (including SSO redirects) to carry the cookie. `lax` is chosen over `strict` because this is an OAuth/SSO callback that must accept an inbound redirect from the SSO provider.
