## Verdict

CONFIRMED. The CSRF protection middleware is configured without session identifier binding, allowing CSRF tokens generated in one session to be replayed in another session.

## Source

**File:** `evals/cases/352/javascript/MissingSessionIdentifierBinding/csrfProtection.js`

**Lines:** 9–20 (the `doubleCsrf()` configuration)

The vulnerability is in the initialization of the CSRF protection middleware. The `doubleCsrf()` function is called without providing a `getSessionIdentifier` callback. According to the code's own comment (lines 5–8), this means the double-submit token is "validated purely against the secret/cookie pair and never checked against which session presented it."

**Exploit path:**

1. Attacker obtains a valid CSRF token by making a legitimate request to `/api/account/csrf-token` in their own authenticated session.
2. The token is valid because it matches the shared secret and cookie, but is not bound to the attacker's session ID.
3. Attacker crafts a malicious request to `/api/account/password` (line 27 of accountRoutes.js) using the token they obtained.
4. The middleware validates the token successfully (because the secret and cookie match) without checking that the token was issued for the victim's session.
5. The victim's password is changed without the victim's knowledge.

The root cause: `csrf-csrf` v4+ requires `getSessionIdentifier` to bind tokens to specific sessions. Omitting it reverts to a weaker double-submit pattern where any valid token works in any session.

## Fix

Add the `getSessionIdentifier` callback to the `doubleCsrf()` configuration in csrfProtection.js:

```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.userId,
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

The `getSessionIdentifier` callback ties each CSRF token to the session that requested it. When the client sends a request with the token, the middleware extracts the session identifier (here, `req.session.userId`) and verifies that the token was issued for that specific session, not just any session.

This prevents cross-session token replay: even if an attacker obtains a valid token from their own session, it will be rejected when used in a victim's session because the session IDs do not match.

The fix uses `req.session.userId` as the session identifier, which is already available in the `requireSession` middleware that protects the routes using this CSRF protection.

## Behaviour changes

None. Legitimate users will see no change in behaviour. The client continues to fetch the token from `/api/account/csrf-token` and includes it in requests to `/api/account/password` and `/api/account/email` exactly as before. The only change is that tokens are now securely bound to sessions, eliminating the cross-session replay vulnerability.
