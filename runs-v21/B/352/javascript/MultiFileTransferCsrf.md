## Verdict

CONFIRMED. The `/api/transfer` POST route performs state-changing operations (money transfer) without CSRF token validation. The route uses session authentication and Origin/Referer header validation, but these are insufficient for CSRF protection. Server-controlled CSRF tokens are required to verify request authenticity and prevent attackers from forging state-changing requests.

## Source

File: `transferRoutes.js`, line 15

The vulnerability occurs in the POST route definition:
```javascript
app.post('/api/transfer', requireSession, (req, res) => {
```

This state-changing endpoint lacks CSRF token validation. It relies only on:
- Session authentication via `requireSession` middleware
- Origin/Referer header validation via `allowSameOriginOrMissing(req)`, which is insufficient as a primary defense

Origin/Referer headers are not server-controlled tokens and cannot reliably prevent CSRF attacks; they serve only as secondary defense-in-depth.

## Fix

The complete fixed file with CSRF token protection using `csrf-csrf` middleware:

### File: transferRoutes.js

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
    getSecret: () => process.env.CSRF_SECRET || 'default-secret-change-me',
    cookieName: '__csrf-token',
    cookieOptions: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    },
    getSessionIdentifier: (req) => req.session?.userId || null
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

## Explanation

The fix implements CSRF token protection using the `csrf-csrf` package, which is the maintained successor to the deprecated `csurf` middleware for Express. 

Key changes:

1. **Import `doubleCsrf`** from the `csrf-csrf` package to set up the CSRF protection mechanism.

2. **Configure `doubleCsrf`** with:
   - `getSecret`: Retrieves the shared secret used to generate tokens (should be a strong, random value stored securely)
   - `cookieName`: Sets the cookie name for the CSRF token
   - `cookieOptions`: Configures the cookie as `httpOnly` (prevents JavaScript access), `secure` (HTTPS-only in production), and `sameSite: 'strict'` (additional browser-level protection)
   - `getSessionIdentifier`: Binds tokens to the user's session ID, ensuring a token issued for one user cannot validate for another

3. **Add `doubleCsrfProtection` middleware** to the `/api/transfer` route after `requireSession`. This middleware will:
   - Expect the CSRF token in either the `x-csrf-token` header (for AJAX/fetch requests) or the `_csrf` body field (for form submissions)
   - Validate the token against the secret and session identifier
   - Return 403 Forbidden if the token is missing or invalid

4. **Retain Origin/Referer validation** as secondary defense-in-depth to provide additional protection against certain attack vectors.

The `getSessionIdentifier` parameter is critical—without it, a token minted for one user would validate for another, defeating the token's purpose. The session binding ensures each token is tied to a specific authenticated session.

## Behaviour changes

- **Client-side impact**: Any client submitting to `/api/transfer` must now include the CSRF token. For fetch/XHR requests, the token must be sent in the `x-csrf-token` header. For form submissions, the token must be included as a `_csrf` field in the request body.
- **Token generation**: A separate GET endpoint would typically be provided (e.g., `GET /api/csrf-token`) to allow clients to obtain a fresh token before making state-changing requests.
- **Security improvement**: The route is now protected against CSRF attacks. Attackers cannot forge valid requests without access to the server-controlled token.
- **Error handling**: Invalid or missing CSRF tokens will result in a 403 Forbidden response, which differs from the previous behavior where only invalid Origin/Referer headers returned 403.
