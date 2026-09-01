## Verdict

**Confirmed CSRF vulnerability.** The POST endpoint at line 15 of `transferRoutes.js` performs a state-changing operation (scheduling a money transfer) but relies solely on Origin/Referer header validation, which is insufficient CSRF protection. The `allowSameOriginOrMissing` function explicitly permits requests with missing Origin and Referer headers (line 7: `if (origin && ...)`), creating a bypass. Token-based CSRF verification is required.

## Source

**File:** `transferRoutes.js`, line 15  
**Call chain:** `transferRoutes.registerTransferRoutes()` → `app.post('/api/transfer', requireSession, handler)` → `csrfOriginPolicy.allowSameOriginOrMissing(req)` validation → `transferLedger.scheduleTransfer()`

**Vulnerability:** The endpoint accepts POST requests from authenticated sessions without verifying a CSRF token. The only protection is an Origin/Referer header check that:
1. Allows requests where both Origin and Referer headers are absent
2. Does not follow the Synchronizer Token Pattern required by the guidance
3. Can be bypassed by attackers who control the Origin header or whose requests carry no Origin/Referer

An attacker can craft a malicious HTML page that, when visited by an authenticated user, submits a form POST to `/api/transfer` with a transfer request. If the user's browser does not send Origin/Referer headers (or sends them under attacker control), the request passes the `allowSameOriginOrMissing` check and executes the transfer.

## Fix

**Step 1: Install CSRF middleware**
```
npm install csrf-csrf cookie-parser
```

**Step 2: Configure the middleware in the Express app initialization (before route registration)**

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();

app.use(cookieParser());
app.use(express.json());

const { doubleCsrfProtection, generateToken } = doubleCsrf({
  getSecret: () => 'your-app-secret-key-change-this',
  getSessionIdentifier: (req) => req.session?.userId || req.sessionID,
  cookieName: '__Host-psifi.x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    path: '/',
  },
});

app.use(doubleCsrfProtection);
```

**Step 3: Modify `transferRoutes.js`**

Replace:
```javascript
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

With:
```javascript
function registerTransferRoutes(app, ledger = new TransferLedger()) {
  app.post('/api/transfer', requireSession, (req, res) => {
    // CSRF token validation is now enforced by doubleCsrfProtection middleware
    // (applied globally; the middleware extracts token from x-csrf-token header or _csrf field)

    const transfer = ledger.scheduleTransfer({
      fromUserId: req.session.userId,
      toAccount: req.body.toAccount,
      amountCents: Number(req.body.amountCents)
    });

    return res.json({ status: 'scheduled', transferId: transfer.id });
  });
}
```

**Step 4: Remove the unused `csrfOriginPolicy.js` import**

The `allowSameOriginOrMissing` check is replaced by `doubleCsrfProtection` middleware and is no longer needed. Remove the import at line 3 of `transferRoutes.js`:
```javascript
const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
```

**Step 5: Client-side token inclusion**

For SPA clients, fetch the CSRF token from a GET endpoint and include it in subsequent POST requests:

```javascript
// On page load, fetch the CSRF token
const csrfToken = await fetch('/api/csrf-token').then(r => r.json()).then(d => d.token);

// Include token in all POST requests
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-csrf-token': csrfToken,
  },
  body: JSON.stringify({ toAccount: 'account123', amountCents: 5000 }),
});
```

For form submissions, include the token in a hidden field:
```html
<form method="POST" action="/api/transfer">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
  <input type="text" name="toAccount" required>
  <input type="number" name="amountCents" required>
  <button type="submit">Transfer</button>
</form>
```

## Explanation

The vulnerability is that the endpoint performs a state-changing operation (money transfer) without verifying a CSRF token. The Origin/Referer header check is insufficient because:
1. It permits requests with missing headers (line 7 of `csrfOriginPolicy.js` allows this via the `if (origin &&` guard)
2. Origin/Referer validation alone does not follow the Synchronizer Token Pattern, which is the industry-standard CSRF defence
3. An attacker can craft a request that bypasses header-based checks

The fix implements the Synchronizer Token Pattern using `csrf-csrf`, the maintained Express middleware for CSRF protection:
- `doubleCsrfProtection` middleware validates a cryptographically random token on every POST request
- The token is bound to the user's session via `getSessionIdentifier`, preventing token reuse across sessions
- The middleware extracts the token from the `x-csrf-token` header (for AJAX/fetch) or `_csrf` form field
- The token is stored in a secure, HttpOnly, SameSite=Strict cookie, preventing XSS exfiltration and cross-site access
- Token validation happens before the route handler executes, blocking forged requests at the middleware layer

This closure implements defence-in-depth: the SameSite cookie attribute prevents the browser from sending the session cookie to cross-site requests, and the token validation blocks any request that does not include the correct server-issued token.

## Behaviour changes

- **Authentication unchanged**: The `requireSession` middleware still enforces that requests must come from an authenticated user.
- **Transfer logic unchanged**: The `ledger.scheduleTransfer()` method continues to work exactly as before.
- **API response unchanged**: The endpoint returns the same JSON response format.
- **New requirement for clients**: All POST requests to `/api/transfer` must now include the CSRF token in the `x-csrf-token` header (AJAX/fetch) or `_csrf` form field (HTML forms). Requests without the token are rejected with a 403 Forbidden response from the middleware. Legitimate clients (SPA, web forms) will fetch the token on page load and include it automatically.
- **Rejected requests**: Forged requests from attacker-controlled cross-site forms are now blocked at the middleware layer before the route handler is invoked, returning 403 Forbidden instead of executing the transfer.
