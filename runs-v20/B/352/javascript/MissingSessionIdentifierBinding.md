## Verdict

exploitable

- cwe_id: CWE-352 (Cross-Site Request Forgery)
- location: `accountRoutes.js:27` (route registration), sink executes at `accountRoutes.js:28` (`accounts.updatePassword(...)`)
- confidence: high

## Source

The `doubleCsrfProtection` middleware built in `csrfProtection.js`, applied to `POST /api/account/password`. `doubleCsrf()` is configured without `getSessionIdentifier`, so the double-submit check validates only that the submitted token cryptographically matches the request's own CSRF cookie (secret + cookie pair) - it never checks which session that cookie/token pair was issued to. Any valid (cookie, token) pair - including one an attacker obtained under their own session, or planted on the victim's browser through a cookie-tossing/related-subdomain vector - passes validation regardless of whose session is attached to the request.

## Fix

### File: csrfProtection.js

```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');

// csrf-csrf v4+ binds each generated token to the session it was issued for
// via getSessionIdentifier. With that supplied, a token is only accepted for
// the session that requested it, so a token obtained under one session
// (e.g. an attacker's own authenticated session) cannot be replayed to pass
// validation for a different victim session.
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.id,
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    httpOnly: true
  }
});

module.exports = { generateCsrfToken, doubleCsrfProtection };
```

## Explanation

`doubleCsrf()` accepts a `getSessionIdentifier` callback that, as of `csrf-csrf` v4, is the mechanism binding a generated token to the session that requested it - each token's HMAC is computed over the session identifier as well as the secret, so `doubleCsrfProtection` now rejects a token/cookie pair on any request whose session identifier does not match the one it was minted for. The fix supplies `getSessionIdentifier: (req) => req.session.id`, the standard `express-session` identifier already implicit in this codebase's use of `req.session.userId`. This closes the finding without touching `accountRoutes.js`: both state-changing routes already run `requireSession` before `doubleCsrfProtection`, so `req.session` (and its `id`) is guaranteed to exist by the time either the token-issuing GET route or the protected POST routes invoke the csrf-csrf callbacks - no reordering or additional guard is needed.

## Behaviour changes

- Tokens generated before this fix is deployed (bound to no session) will fail validation afterward, so any client holding a pre-fix token must call `GET /api/account/csrf-token` again to obtain a session-bound one before its next POST. This is the intended effect of closing the weakness, not incidental breakage - the endpoint already exists for clients to fetch a fresh token on demand.
- No other argument, default, return value, or error path in `doubleCsrf()`'s configuration was changed; `getSecret`, `cookieName`, and `cookieOptions` are untouched, and `accountRoutes.js` is unmodified.

verification: `node --check` on the fixed `csrfProtection.js` (run against a scratch copy, not the case directory) - passed, no syntax errors. The `getSessionIdentifier` option name and its v4 binding requirement come from this repository's own loaded `cwe/352/javascript/INDEX.md` guidance, not from recall. A live check that a cross-session token replay is actually rejected would require standing up the app with a real session store and two authenticated sessions, which was not run; only static/syntax verification was performed.

assumptions: assumed the codebase's session middleware is `express-session` (consistent with the existing `req.session.userId` usage), so `req.session.id` is a valid, always-present identifier once `requireSession` has passed - this was not confirmed against the project's `package.json` since no such session store).
