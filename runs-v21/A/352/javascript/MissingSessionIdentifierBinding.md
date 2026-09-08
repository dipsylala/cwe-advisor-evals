## Verdict

CONFIRMED. The `doubleCsrf()` configuration omits `getSessionIdentifier`, allowing CSRF tokens generated for one session to validate for any other session. This violates session binding and enables cross-session token reuse attacks.

## Source

File: `csrfProtection.js`

The vulnerability is in the `doubleCsrf()` initialization on lines 9–20. The configuration lacks the required `getSessionIdentifier` callback, which binds each token to the session that generated it. The inline comment (lines 5–8) explicitly documents this gap: "csrf-csrf v4+ requires getSessionIdentifier to bind each generated token to the session it was issued for. It is omitted here, so the double-submit token is validated purely against the secret/cookie pair and never checked against which session presented it."

Without session binding, an attacker can steal a valid CSRF token from one user's session and successfully replay it in another user's session, bypassing the CSRF protection entirely.

## Fix

### File: csrfProtection.js

```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session?.userId,
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

The fix adds the `getSessionIdentifier` callback to the `doubleCsrf()` configuration. This callback receives the request object and returns a unique identifier for the current session (`req.session.userId`), which is populated by the `requireSession` middleware in the request handlers.

With this change:
- During token generation via `generateCsrfToken(req, res)`, the token is cryptographically bound to the session ID
- During validation via `doubleCsrfProtection` middleware, the token is checked against both the secret/cookie pair AND the current session ID
- A token minted for user A will no longer validate when presented by user B, closing the cross-session reuse attack vector

This aligns with `csrf-csrf` v4+ requirements and the cwe-advisor remediation guidance that mandates session binding as the mechanism preventing token portability across sessions.
