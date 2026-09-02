## Verdict

**CONFIRMED VULNERABILITY**: CWE-352 (CSRF) at line 15 of transferRoutes.js

The POST endpoint `/api/transfer` lacks CSRF token validation. Current protection relies solely on Origin/Referer header validation, which is insufficient. Per CWE-352 guidance, all state-changing operations require token-based CSRF verification.

## Source

**Attack vector**: Cross-site attacker crafts a request to `POST /api/transfer` while a victim with an active session visits the attacker's page. The Origin/Referer header check is not a reliable CSRF defence.

**Data flow**: 
1. Attacker-controlled request reaches `app.post('/api/transfer', ...)` at line 15
2. Session validation passes (requireSession middleware)
3. Origin/Referer check passes (or request is made without these headers from certain contexts)
4. Transfer is scheduled without CSRF token validation
5. Financial operation executes unprotected

**Sink**: Line 15 route handler accepting POST without `doubleCsrfProtection` middleware. Per JavaScript guidance, taint sink is defined as `app.post()` routes not behind `doubleCsrfProtection` middleware.

## Fix

Install and configure CSRF middleware:
```
npm install csrf-csrf cookie-parser
```

**Fixed code** for transferRoutes.js:

```javascript
'use strict';

const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
const { TransferLedger } = require('./transferLedger');
const { doubleCsrf } = require('csrf-csrf');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  const { doubleCsrfProtection } = doubleCsrf({
    getSecret: () => process.env.CSRF_SECRET || 'default-secret',
    getSessionIdentifier: (req) => req.session.userId,
    cookieName: '__csrf-token',
    cookieOptions: { httpOnly: true, secure: true, sameSite: 'strict' }
  });

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

**Key changes**:
- Import `doubleCsrf` from `csrf-csrf`
- Configure middleware with `getSecret`, `getSessionIdentifier` (binds token to user's session), and cookie options including `sameSite: 'strict'`
- Add `doubleCsrfProtection` middleware to the POST route before the handler function
- `getSessionIdentifier` is required as of v4 to prevent token reuse across sessions

**Client-side requirement**: Update clients to send the CSRF token in the `x-csrf-token` request header (for fetch/XHR) or `_csrf` body field (for forms). Tokens must be obtained from the server via a GET endpoint using `generateCsrfToken(req, res)`.

## Explanation

The vulnerability exists because the route processes a state-changing operation (financial transfer) without validating a CSRF token. Origin/Referer header validation is listed in the guidance as "defence-in-depth" alongside the token, not a replacement for it—it is browser-enforced and unreliable in all contexts.

The fix implements token-based CSRF protection by:
1. Configuring `csrf-csrf` middleware with `doubleCsrfProtection` 
2. Binding tokens to the user's session identifier via `getSessionIdentifier` so a token minted for one user cannot validate for another
3. Setting `sameSite: 'strict'` on the cookie as secondary defence-in-depth
4. Adding the middleware to the vulnerable route so all POST requests must include a valid token

The middleware automatically validates tokens sent in `x-csrf-token` header or `_csrf` body field. Requests without valid tokens receive a 403 response. The Origin/Referer check remains in place for additional validation.

## Behaviour changes

- Requests to `POST /api/transfer` without a valid CSRF token are rejected with HTTP 403
- Clients must obtain a CSRF token from a server-provided GET endpoint and include it in subsequent requests
- The endpoint now requires token inclusion for all POST requests, blocking cross-site form submissions and AJAX requests that lack the token
- Session binding via `getSessionIdentifier` ensures tokens cannot be replayed across different user sessions
