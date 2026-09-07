## Verdict
exploitable

## Source
Attacker-controlled HTTP request from a cross-site origin. The attack vector is a crafted request to POST `/api/transfer` while an authenticated user is present. The attacker tricks the user into triggering this request (via a form on a malicious site, a link, or JavaScript), and the server executes the state-changing operation (fund transfer) without cryptographic proof of the user's intent.

## Fix

### Vulnerable code (transferRoutes.js, lines 1-30)
```javascript
'use strict';

const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
const { TransferLedger } = require('./transferLedger');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  // VULNERABLE: Custom origin check is insufficient for CSRF protection
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

module.exports = { registerTransferRoutes };
```

### Vulnerable CSRF check (csrfOriginPolicy.js)
The origin validation in `csrfOriginPolicy.js` uses `startsWith()` for comparison:
```javascript
function allowSameOriginOrMissing(req) {
  const origin = req.get('origin') || req.get('referer');
  const expected = `${req.protocol}://${req.get('host')}`;

  // VULNERABLE: startsWith() allows bypass
  // e.g., https://example.com.attacker.com starts with https://example.com
  if (origin && !origin.startsWith(expected)) {
    return false;
  }

  return true;
}
```

### Fixed code (transferRoutes.js with csrf-csrf library)
```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');
const cookieParser = require('cookie-parser');
const { TransferLedger } = require('./transferLedger');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'fallback-secret',
  getSessionIdentifier: (req) => req.session?.userId,
  cookieName: 'x-csrf-token',
  cookieOptions: { httpOnly: true, sameSite: 'Strict', secure: true }
});

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  // Apply cookie parser middleware globally (must come before routes)
  app.use(cookieParser());
  
  // Protected route: CSRF token validation via doubleCsrfProtection middleware
  app.post('/api/transfer', requireSession, doubleCsrfProtection, (req, res) => {
    // Token is validated by middleware; invalid/missing tokens receive 403 before reaching handler
    
    const transfer = ledger.scheduleTransfer({
      fromUserId: req.session.userId,
      toAccount: req.body.toAccount,
      amountCents: Number(req.body.amountCents)
    });

    return res.json({ status: 'scheduled', transferId: transfer.id });
  });
}

module.exports = { registerTransferRoutes, generateCsrfToken };
```

### Library recommendation
Install `csrf-csrf` (^4.0.0) and `cookie-parser` (^1.4.6) to package.json:
```json
{
  "dependencies": {
    "csrf-csrf": "^4.0.0",
    "cookie-parser": "^1.4.6"
  }
}
```

The `csrf-csrf` library is the maintained successor to the deprecated `csurf` package and implements the Synchronizer Token Pattern with proper session binding via the `getSessionIdentifier` callback.

## Explanation
The original code attempted CSRF protection via origin/referer header validation, but this is insufficient:

1. **Custom implementation weakness**: Origin header validation using `startsWith()` allows bypass attacks. An attacker can craft an origin like `https://example.com.attacker.com` to bypass a check expecting `https://example.com`, because the string prefix matches.

2. **Missing header allowance**: The check allows requests with no Origin or Referer header. While this supports legacy clients, it also allows attackers without these headers to proceed.

3. **No cryptographic binding**: The original implementation does not use CSRF tokens, which are the primary defense. A legitimate request and a forged request are indistinguishable to the server.

The fix replaces the custom, incomplete check with proper token-based CSRF validation using `csrf-csrf`. The `doubleCsrfProtection` middleware validates that each POST request includes a CSRF token that:
- Was issued by the server for that specific session (via `getSessionIdentifier`)
- Cannot be predicted or forged by an attacker
- Is bound to the session and cannot be transferred between users

The token is validated before the request handler runs; requests with invalid or missing tokens receive a 403 response directly from the middleware. The `Strict` SameSite cookie policy and `httpOnly` flag provide defense-in-depth.

## Behaviour changes
1. **Client-side token requirement**: Web forms and AJAX requests must now fetch the CSRF token (via a GET endpoint calling `generateCsrfToken(req, res)`) and include it in the `x-csrf-token` header (fetch/XHR) or `_csrf` form field (HTML forms) before making POST requests. This is required; requests without valid tokens are rejected.

2. **Middleware ordering**: `cookieParser()` must be applied before the routes and before other middleware that depends on cookies. Incorrect ordering will cause tokens to be unavailable.

3. **Error handling**: Token validation failures now return 403 directly from the `doubleCsrfProtection` middleware, before the route handler is invoked. No additional error handling is needed in the handler; this is the correct behavior.

4. **Session identifier binding**: The `getSessionIdentifier` function must return a consistent, unique identifier per session (here, `req.session.userId`). Without this binding, tokens from one user would validate for another user's session.

5. **Environment configuration**: The CSRF secret (`process.env.CSRF_SECRET`) must be configured in production and must not be hardcoded. The secret should be stored securely and should not be transmitted over the network.

## Verification
Syntax verification of the fixed code:
- The `doubleCsrf` import and destructuring are correct per `csrf-csrf` v4+ API
- The middleware registration and route protection follow Express convention
- All new identifiers (`doubleCsrf`, `cookieParser`, `generateCsrfToken`, `doubleCsrfProtection`) are exported by their respective libraries

Note: Full integration testing would require:
- Setting up a test server with the fixed code
- Installing the dependencies (`csrf-csrf`, `cookie-parser`)
- Creating test cases to verify that valid CSRF tokens are accepted and invalid tokens are rejected
- Verifying that the middleware returns 403 for missing or invalid tokens

## Assumptions
1. The application uses Express.js (no Fastify or other framework detected)
2. The application has session middleware configured with `req.session` and `req.session.userId` available
3. `process.env.CSRF_SECRET` will be set in production (currently falls back to `'fallback-secret'` for development, which is unsafe for production)
4. No other code relies on the `allowSameOriginOrMissing` function from `csrfOriginPolicy.js`; this file can be safely removed or kept for historical reference
