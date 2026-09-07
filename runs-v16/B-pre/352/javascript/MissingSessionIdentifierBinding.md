## Verdict
Exploitable

## Source
`req.body.newPassword` (unauthenticated state-changing request due to missing session binding in CSRF protection)

## Fix

**Vulnerable code (accountRoutes.js, lines 3-30):**
```javascript
const { generateCsrfToken, doubleCsrfProtection } = require('./csrfProtection');
const { AccountStore } = require('./accountStore');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerAccountRoutes(app, accounts = new AccountStore()) {
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
```

**Fixed code (accountRoutes.js, lines 1-35):**
```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');
const { AccountStore } = require('./accountStore');

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'default-secret-change-in-production',
  getSessionIdentifier: (req) => req.session.id,
  cookieName: '_csrf',
  cookieOptions: { httpOnly: true, secure: true, sameSite: 'Strict' }
});

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerAccountRoutes(app, accounts = new AccountStore()) {
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
The vulnerability exists because the CSRF middleware was not properly configured with session binding. The original code imported pre-instantiated middleware from `./csrfProtection` without ensuring the `getSessionIdentifier` parameter was set, which is required as of csrf-csrf v4 to bind tokens to individual sessions. Without this binding, a CSRF token minted for one user could validate for another user's request. The fix configures `doubleCsrf` with an explicit `getSessionIdentifier` callback that returns `req.session.id`, ensuring each session gets its own unique token that cannot be replayed across sessions. The `SameSite=Strict` cookie option and `httpOnly` flag provide defence-in-depth protection. The session identifier binding is the primary fix that closes the reuse vulnerability.

## Behaviour changes
- The import changes from a local `csrfProtection` module to direct import of `doubleCsrf` from the `csrf-csrf` library, requiring `npm install csrf-csrf` if not already present
- The middleware is now instantiated inline with explicit configuration instead of importing pre-instantiated utilities
- `cookieOptions` now explicitly sets `httpOnly: true` and `secure: true` (original configuration unknown, assumed permissive)
- `SameSite` is set to `Strict` for maximum protection (alternative is `Lax` for broader compatibility)
- A `CSRF_SECRET` environment variable can be used for secret management, falling back to a default in development (production deployment must set this env var)
- The middleware contract remains identical: it validates the CSRF token from the request and rejects on mismatch with a 403 response
