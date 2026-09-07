## Verdict

Exploitable. The POST endpoint at line 15 accepts state-changing requests (fund transfer) from authenticated users but relies solely on Origin/Referer header validation for CSRF protection. The guidance specifies that Origin/Referer validation is defence-in-depth only and that all state-changing endpoints must implement server-controlled CSRF token validation using the Synchronizer Token Pattern. Attackers can craft cross-site requests that bypass Origin/Referer checks in certain scenarios (missing headers, proxy configurations) or use same-site gadgets to forge requests.

## Source

Attacker-controlled request parameters (`req.body.toAccount`, `req.body.amountCents`) submitted to the POST endpoint via cross-site forgery, reaching the business logic without CSRF token validation.

## Fix

### File: transferRoutes.js

```javascript
'use strict';

const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
const { TransferLedger } = require('./transferLedger');
const { doubleCsrf } = require('csrf-csrf');

// Configure CSRF protection with session-bound token validation
const { doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'development-secret',
  getSessionIdentifier: (req) => req.session?.userId,
  cookieName: 'x-csrf-token',
  cookieOptions: { httpOnly: false, secure: true, sameSite: 'strict' }
});

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  app.post('/api/transfer', requireSession, doubleCsrfProtection, (req, res) => {
    if (!allowSameOriginOrMissing(req)) {
      return res.status(403).json({ error: 'cross-site request rejected' });
    }

    const transfer = ledger.scheduleTransfer({
      fromUserId: req.session.userId,
      toAccount: req.body.toAccount,
      amountCents: Number(req.body.amountCents)
    });

    return res.json({ status: 'scheduled', transferId: transfer.id });
  });
}

module.exports = { registerTransferRoutes };
```

## Explanation

The fix implements CSRF token validation using the `csrf-csrf` library (the maintained successor to the deprecated `csurf`), which enforces the Synchronizer Token Pattern. The `doubleCsrfProtection` middleware is applied to the POST endpoint immediately after the `requireSession` middleware, ensuring all authenticated requests are validated before processing. The middleware automatically rejects requests missing valid CSRF tokens in the `x-csrf-token` header or `_csrf` body field. Token generation and validation are bound to the user's session via `getSessionIdentifier`, preventing token replay across sessions. The cookie is configured with `SameSite=strict` for defence-in-depth and `httpOnly=false` to allow XHR/fetch clients to read and send the token. The existing Origin/Referer validation remains as supplementary protection. This eliminates the CSRF vulnerability by ensuring that state-changing requests originate from the legitimate application rather than cross-site attackers.

## Behaviour changes

**Middleware execution order:** The `doubleCsrfProtection` middleware is inserted between `requireSession` and the route handler. Requests without valid CSRF tokens now receive a 403 response from the middleware before reaching the business logic, whereas previously all authenticated requests proceeded directly to the transfer logic.

**Token validation:** All POST requests to `/api/transfer` must now include a valid CSRF token in either the `x-csrf-token` header (for XHR/fetch) or `_csrf` form field. Clients that do not supply the token will be rejected with 403 Forbidden.

**Cookie attribute:** The CSRF cookie is now configured with `secure=true` and `sameSite=strict`, which are stricter than the original implementation. The `secure` flag restricts transmission to HTTPS only; `sameSite=strict` prevents cross-site cookie transmission entirely.

**Failure modes:** Invalid or missing tokens now result in middleware rejection before business logic executes, preventing invalid transfer scheduling rather than allowing the request through.

