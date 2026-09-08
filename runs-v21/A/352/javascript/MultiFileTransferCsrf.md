## Verdict

The endpoint performs a sensitive financial operation (scheduling a money transfer) without proper CSRF protection. While it includes an origin/referer header check, this alone is insufficient to prevent CSRF attacks because:

1. The check allows missing origin headers, which browsers may not send due to privacy settings or certain request contexts
2. Origin/referer validation is a secondary defense; the primary defense is a CSRF token mechanism

The vulnerability is confirmed: an attacker can forge a cross-site request to transfer funds from a logged-in user's account.

## Source

**File:** `transferRoutes.js`, line 15  
**Operation:** `app.post('/api/transfer', ...)` - a state-changing endpoint that schedules a monetary transfer  
**Data Flow:** 
- User session ID from `req.session.userId` (authenticated)
- User-supplied transfer parameters from `req.body.toAccount` and `req.body.amountCents` (untrusted)
- Insufficient protection: only `allowSameOriginOrMissing()` validation, which allows requests with missing origin headers

**Why insufficient:** The origin/referer header check does not block all CSRF vectors. Browsers may not send origin headers in certain contexts (cross-origin requests, privacy-sensitive scenarios), and a header-only defense leaves the endpoint vulnerable.

## Fix

### File: transferRoutes.js

```javascript
'use strict';

const csrf = require('csurf');
const { TransferLedger } = require('./transferLedger');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

const csrfProtection = csrf({ cookie: false });

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  app.post('/api/transfer', requireSession, csrfProtection, (req, res) => {
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

The fix applies the `csurf` middleware's CSRF protection to the transfer endpoint. This implements the synchronizer token pattern:

1. **`const csrf = require('csurf')`** — Import the CSRF middleware library, which generates and validates unique CSRF tokens per session
2. **`const csrfProtection = csrf({ cookie: false })`** — Create a CSRF middleware instance configured to store tokens in the session (not cookies), ensuring tokens are session-bound and unique per user
3. **Added `csrfProtection` middleware** — The middleware is inserted into the POST request chain after `requireSession`, so it only protects authenticated requests. The middleware automatically validates the incoming CSRF token against the session's stored token before the handler executes
4. **Removed origin/referer check** — The `allowSameOriginOrMissing()` check is removed because the CSRF token is the primary and sufficient defense. Token validation is enforced; no forged request can provide a valid token it has never seen

The client must obtain a valid CSRF token from the server (typically via a GET endpoint that returns it) and include it in the POST request body as `_csrf` (default field name for `csurf`), or as a header. Without the correct token, the request is rejected with a 403 error before the transfer handler runs.
