## Verdict

Exploitable. `res.cookie('auth_token', ...)` at line 15 sets an authentication cookie with `httpOnly: true` but no `secure: true`, so a browser will attach and transmit `auth_token` over a plain-HTTP connection to the same host if one is reachable (mixed content, a misconfigured link, a downgrade), exposing the token to network interception even though the site is intended to run over HTTPS.

## Source

`req.query.token` at line 8 - the signed session token returned by the SSO provider as a query parameter on the callback redirect. It flows unchanged into `authToken` and then directly into the cookie value at line 15 (only a presence check at line 10, no transport-attribute handling).

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
    maxAge: 86400000,
  });

  res.redirect('/dashboard');
});

module.exports = router;
```

## Explanation

Added `secure: true` to the `res.cookie()` options at the identified sink so Express emits the `Secure` attribute on the `Set-Cookie` header for `auth_token`. With `Secure` set, the browser will only ever attach this cookie to requests made over HTTPS, closing the plaintext-transmission path the finding reports; `httpOnly` and `maxAge` are unchanged since they already matched the guidance and were not part of this weakness. No library change is required - this is a first-party `res.cookie()` call in Express itself, not a session-management dependency.

## Behaviour changes

- Added `secure: true`: the cookie will no longer be sent by the browser over an HTTP connection to this host. This is the intended effect of the fix. It requires the application to actually be served over HTTPS in production; if any legitimate request path still reaches this route over plain HTTP, the cookie would silently stop being stored by the browser (Chrome/Firefox) or trigger a login loop rather than an insecure-cookie finding.
- If this router sits behind a reverse proxy (TLS terminated upstream, plain HTTP to Node), Express must have `app.set('trust proxy', ...)` configured at the application level for `req.secure`-dependent behavior to work correctly; this file only defines a router and does not have access to the `app` instance, so that setting could not be verified or changed here. `res.cookie()`'s own `secure` option is not conditional on `trust proxy` (unlike `express-session`), so the `Secure` attribute will be emitted regardless - this note is a deployment prerequisite for the cookie to be usable end-to-end, not a gap in this fix.
- No other arguments, return values, or control flow were changed. `sameSite` was left unset (Express's default, `Lax`) rather than adding an explicit value: this endpoint is an inbound SSO/OAuth callback, and the loaded guidance specifically warns that `SameSite=Strict` withholds cookies from such flows, so introducing a stricter value here would be an unrelated behavior change outside the scope of the reported `Secure`-flag finding.

## Verification

`node --check` was run against the fixed file (copied to a scratch location outside the repository, not the case fixture) and returned no errors. No new imports, dependencies, or API names were introduced - only an added key (`secure: true`) in an object literal already passed to the existing `res.cookie()` call - so no further dependency or symbol verification was needed.

## Assumptions

- Assumed the application is deployed with HTTPS enforced site-wide (stated as a prerequisite in the general and JavaScript-specific guidance); the fix does not itself add HTTPS enforcement, only the `Secure` cookie attribute that depends on it.
- Left `sameSite` unset rather than guessing `Lax` or `Strict` explicitly, since this route is a cross-site SSO callback and the guidance warns against defaulting to `Strict` for such flows; Express's implicit default (`Lax`) applies unchanged. Confidence: high - the fix is a single, guidance-specified attribute addition to an already-identified sink.
