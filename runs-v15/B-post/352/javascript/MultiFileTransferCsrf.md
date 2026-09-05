## Verdict

Exploitable

## Source

HTTP POST request parameters `req.body.toAccount` and `req.body.amountCents` from an unauthenticated attacker's crafted cross-site request. The vulnerability is exploited when an authenticated user visits an attacker-controlled page that submits a form to the transfer endpoint, causing the user's browser to send the session cookie with the malicious transfer request.

## Fix

**Vulnerable code:**

```javascript
const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
const { TransferLedger } = require('./transferLedger');

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
  app.post('/api/transfer', requireSession, (req, res) => {
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
```

**Fixed code:**

```javascript
const { doubleCsrf } = require('csrf-csrf');
const cookieParser = require('cookie-parser');
const { TransferLedger } = require('./transferLedger');

const { doubleCsrfProtection, generateToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'default-secret-change-in-production',
  getSessionIdentifier: (req) => req.session.userId,
  cookieName: 'x-csrf-token',
  cookieOptions: { httpOnly: true, sameSite: 'strict', secure: true }
});

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  // Apply cookie parser before CSRF middleware
  app.use(cookieParser());

  // Middleware to generate CSRF token for GET requests
  app.get('/api/transfer/token', requireSession, (req, res) => {
    const csrfToken = generateToken(req, res);
    return res.json({ csrfToken });
  });

  // Protected transfer endpoint with CSRF validation
  app.post('/api/transfer', requireSession, doubleCsrfProtection, (req, res) => {
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

The vulnerability is closed by replacing the insufficient origin/referer header check with proper CSRF token validation using the `csrf-csrf` library, the maintained successor to the deprecated `csurf`. The fixed code:

1. Installs `csrf-csrf` middleware which implements the Synchronizer Token Pattern with cryptographically random 256-bit tokens
2. Applies `doubleCsrfProtection` middleware to the POST `/api/transfer` route, which validates that every state-changing request includes a valid CSRF token
3. Binds the token to the user's session via `getSessionIdentifier`, preventing token reuse across sessions
4. Sets the `SameSite=Strict` cookie attribute as defense-in-depth (blocks cookie transmission on cross-site requests at the browser level)
5. Exposes a `/api/transfer/token` endpoint that the client calls first to obtain a fresh token before making the transfer request
6. The token must be sent in the `x-csrf-token` header (for AJAX/fetch) or `_csrf` body field (for forms) on the POST request; `csrf-csrf` validates this automatically

The origin/referer check is removed because it allows missing headers (a flaw in `allowSameOriginOrMissing`), whereas token validation requires the token to be present and cryptographically correct.

## Behaviour changes

1. **New dependency**: Requires `npm install csrf-csrf cookie-parser` - both are widely maintained packages used in production Express applications
2. **Token generation endpoint**: Clients must call `/api/transfer/token` before initiating a transfer to obtain a fresh token; the GET endpoint is lightweight and session-gated so this is not a performance concern
3. **Token transmission**: The client must include the token in either the `x-csrf-token` request header (for XHR/fetch) or `_csrf` form field (for form submissions); this is a client-side requirement only
4. **Session binding**: Tokens are scoped to `req.session.userId`, so a token obtained by one user cannot be used for another user's session, even if compromised
5. **Cookie attributes**: The CSRF token cookie is now `httpOnly`, `sameSite: strict`, and `secure`, preventing JavaScript access and cross-site transmission
6. **Environment variable**: The code references `process.env.CSRF_SECRET` which must be set to a strong random value in production; the default shown here is for development only and must be changed
7. **No functional change to the transfer logic**: The transfer scheduling still receives the same `fromUserId`, `toAccount`, and `amountCents` and returns the same response structure; the fix only adds authentication of the request origin
