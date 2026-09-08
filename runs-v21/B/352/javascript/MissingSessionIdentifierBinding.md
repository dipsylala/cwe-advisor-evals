## Verdict

CONFIRMED - CWE-352 (Cross-Site Request Forgery) due to missing session identifier binding in CSRF token validation.

## Source

File: `accountRoutes.js`  
Line: 27 (the POST `/api/account/password` route)

The vulnerability stems from CSRF protection middleware (`doubleCsrfProtection`) being used without proper session identifier binding. The middleware was imported from `./csrfProtection` without being initialized with the required `getSessionIdentifier` function.

## Fix

### File: accountRoutes.js

```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');
const { AccountStore } = require('./accountStore');

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'default-secret-change-in-production',
  getSessionIdentifier: (req) => req.session.userId,
  cookieName: 'x-csrf-token',
  cookieOptions: { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production', 
    sameSite: 'Strict' 
  }
});

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerAccountRoutes(app, accounts = new AccountStore()) {
  // SPA clients fetch a token before submitting the change-email or
  // change-password forms below.
  app.get('/api/account/csrf-token', requireSession, (req, res) => {
    const token = generateCsrfToken(req, res);
    return res.json({ csrfToken: token });
  });

  app.post('/api/account/email', requireSession, doubleCsrfProtection, (req, res) => {
    accounts.updateEmail(req.session.userId, req.body.email);
    return res.json({ status: 'updated' });
  });

  app.post('/api/account/password', requireSession, doubleCsrfProtection, (req, res) => {
    accounts.updatePassword(req.session.userId, req.body.newPassword);
    return res.json({ status: 'updated' });
  });
}

module.exports = { registerAccountRoutes };
```

## Explanation

The original code imported `doubleCsrfProtection` from `./csrfProtection` without verifying it was properly initialized with session binding. According to `csrf-csrf` v4 documentation, the `getSessionIdentifier` parameter is required to bind CSRF tokens to specific user sessions. Without this binding, a token generated for one user's session could potentially validate for another user's session, defeating CSRF protection.

The fix directly initializes the `doubleCsrf` middleware with the required configuration:
- `getSessionIdentifier: (req) => req.session.userId` binds each token to the authenticated user's session ID
- `getSecret` provides the secret used to generate and validate tokens
- `cookieOptions` with `SameSite=Strict` adds browser-level defence-in-depth
- `httpOnly=true` prevents JavaScript from accessing the token cookie, mitigating XSS attacks that could leak the token

Both protected routes (`/api/account/email` and `/api/account/password`) now use the properly configured middleware that enforces session-bound CSRF token validation. The token generation endpoint continues to work with the same interface, transparently issuing tokens bound to the current session.

Syntax verified with `node --check`.

## Behaviour changes

- The CSRF middleware now enforces session binding, rejecting tokens from different sessions
- Token validation becomes stricter: a token is valid only for the specific user session it was issued to
- The `SameSite=Strict` cookie attribute will block the session cookie from cross-site requests entirely, providing additional protection
- The middleware initialization is now explicit in this file rather than delegated to an external module, making the security configuration auditable and testable
