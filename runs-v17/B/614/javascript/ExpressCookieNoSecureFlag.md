## Verdict

The finding is valid. Line 15 sets a sensitive authentication cookie without the `secure` flag, allowing potential transmission over unencrypted HTTP connections and exposure to man-in-the-middle attacks.

## Source

**File**: `ExpressCookieNoSecureFlag.js`  
**Line**: 15  
**Function**: Route handler for `/sso/callback`

The authentication token is received from an SSO provider via query parameter (`req.query.token`) and stored in a cookie via `res.cookie()`. The cookie contains sensitive session/authentication data but lacks the `secure` flag.

**Data flow**:
1. Attacker-controlled source: `req.query.token` from SSO callback
2. Validation: None (assumes SSO provider is trusted)
3. Sink: `res.cookie('auth_token', authToken, {...})` at line 15-18
4. Missing protection: `secure: true` is not set, so cookie can transmit over HTTP

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
    secure: true,
    httpOnly: true,
    maxAge: 86400000,
  });

  res.redirect('/dashboard');
});

module.exports = router;
```

## Explanation

Added `secure: true` to the cookie options object. This enforces that the browser only sends the authentication cookie over HTTPS connections, preventing interception on unencrypted HTTP links. The fix combines with the existing `httpOnly: true` (preventing XSS-based cookie theft) to provide defense-in-depth.

The fix preserves all existing behavior: the cookie still has a 1-day expiration (`maxAge: 86400000`), remains inaccessible to JavaScript, and is sent on all same-site requests. The only change is transport-layer enforcement.

**Verification**: Node.js syntax check passed. The fix matches Express.js documentation for the `secure` cookie option.

## Behaviour changes

- **Transport restriction**: Cookie now only transmits over HTTPS; attempting to set it over HTTP will fail silently (no Set-Cookie header sent) if the application is not behind a properly-configured proxy.
- **Prerequisite**: Application must run on HTTPS in production for secure cookies to work. If behind a reverse proxy (nginx, load balancer), Express must be configured with `app.set('trust proxy', 1)` or equivalent so it correctly detects HTTPS.
- **No functional change for HTTPS clients**: For browsers connecting over HTTPS (the normal production path), behavior is identical to before, except the cookie is now protected from network-layer interception.
