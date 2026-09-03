## Verdict

**Confirmed vulnerability.** The POST endpoint at line 15 lacks CSRF token validation. Origin header checking alone is insufficient for CSRF protection because the Origin header can be missing in legitimate requests (e.g., same-origin requests from forms, same-site requests in certain browser configurations) and must not be relied upon as the sole defence.

## Source

HTTP request from attacker's website. An attacker crafts HTML or JavaScript that makes a POST request to `/api/transfer` while the authenticated user is on the attacker's site. The browser automatically includes the session cookie. Since the endpoint does not validate a CSRF token, the transfer executes without confirming the user intended to authorize it.

## Fix

Install `csrf-csrf` and set up token validation:

```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');
const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
const { TransferLedger } = require('./transferLedger');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  const { doubleCsrfProtection } = doubleCsrf({
    getSecret: () => 'your-app-secret',
    getSessionIdentifier: (req) => req.session.userId,
    cookieName: '__Host-psifi.x-csrf-token'
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

**Library dependency:**  
Add `csrf-csrf` to `package.json` dependencies. Use the version specified by your SCA/dependency-check tooling; the guidance does not prescribe a specific version.

**Client-side requirement:**  
The client must include the CSRF token in requests. For AJAX/fetch requests, send it in the `x-csrf-token` header:

```javascript
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'x-csrf-token': csrfTokenValue
  },
  credentials: 'include',
  body: JSON.stringify({ toAccount, amountCents })
});
```

## Explanation

The fix adds `doubleCsrf` middleware from the `csrf-csrf` library. The middleware:

1. **Binds the token to the session** using `getSessionIdentifier: (req) => req.session.userId`, ensuring a token minted for one user cannot validate for another.
2. **Validates the token** on every POST request before the handler executes, rejecting the request with a 403 if the token is missing or invalid.
3. **Protects against token forgery** by validating the server-controlled secret and session binding.

The origin header check remains as defence-in-depth but is no longer the sole protection. The CSRF token is now the primary defence, preventing cross-site POST requests even if the origin header is missing or spoofed. The `SameSite=Lax` default in modern cookie handling provides additional browser-level protection.

The fix preserves the endpoint's existing behaviour: authenticated users with valid CSRF tokens continue to execute transfers normally, and the `requireSession` middleware still enforces login requirements.

## Behaviour changes

- **Adds new dependency:** `csrf-csrf` must be installed and initialized.
- **Token validation:** All POST requests now require a valid CSRF token in the `x-csrf-token` header or `_csrf` body field. Requests without a valid token receive a 403 response.
- **Client-side impact:** AJAX requests and forms must be updated to include the CSRF token before sending. For SPA clients, the token can be fetched from a GET endpoint or injected into the initial page render.
- **Error handling:** Requests rejected by CSRF validation now explicitly fail with 403, providing security-relevant feedback to the client.
- **Session binding:** Tokens are regenerated per session; users who log in receive a new token, preventing pre-authentication token replay.
