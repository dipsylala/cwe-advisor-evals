## Verdict

**Confirmed: CWE-352 (Cross-Site Request Forgery)**

The POST endpoint lacks proper CSRF protection. The origin validation using `startsWith()` is insufficient and can be bypassed. Additionally, there is no CSRF token validation, relying solely on origin/referer headers which attackers can forge or control in certain contexts.

## Source

**File:** `evals/cases/352/javascript/MultiFileTransferCsrf/transferRoutes.js` line 15

**Call chain:**
1. `registerTransferRoutes()` exposes POST `/api/transfer` endpoint (line 15)
2. Endpoint calls `allowSameOriginOrMissing(req)` from `csrfOriginPolicy.js` for origin validation (line 16)
3. `allowSameOriginOrMissing()` uses `startsWith()` comparison (line 7 of csrfOriginPolicy.js), which is too lenient

**Vulnerability:** The origin check at line 7 of csrfOriginPolicy.js uses `origin.startsWith(expected)`, allowing subdomain-based bypasses (e.g., `http://example.com.attacker.com` would bypass a check for `http://example.com`). More critically, the endpoint relies entirely on origin/referer validation without CSRF token validation, which is insufficient protection.

## Fix

Replace the origin-only validation with proper CSRF token middleware. Here is the corrected `transferRoutes.js`:

```javascript
'use strict';

const csrf = require('csurf');
const { TransferLedger } = require('./transferLedger');

// CSRF protection middleware
const csrfProtection = csrf({ cookie: false });

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

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

The `csrfProtection` middleware validates the CSRF token from the request body (or headers), which is cryptographically tied to the user's session and cannot be forged by a cross-site attacker.

## Explanation

CSRF attacks succeed when an attacker tricks a user into submitting a request to a sensitive endpoint (like a money transfer) from a malicious site. The victim's browser automatically includes session cookies, so the attack succeeds if the endpoint trusts cookies alone.

The original code attempted defense by checking `origin` and `referer` headers, but this is insufficient:

1. **Lenient origin matching:** The `startsWith()` check allows bypass—an attacker at `evil.com.transfer-app.com` can match origin validation for `transfer-app.com`.

2. **No token validation:** Origin/referer headers are not a cryptographic defense. Proper CSRF protection requires a token that:
   - Is cryptographically generated and tied to the user's session
   - Cannot be read or guessed by JavaScript on a cross-origin page
   - Must be submitted back in the request body or a custom header (not a cookie)

The fix introduces the `csurf` middleware (or equivalent CSRF token middleware), which:
- Generates a unique token per session
- Validates the token on POST requests
- Rejects requests without a valid token, even if cookies are present

This is the standard defense-in-depth approach for CSRF protection in Express applications.
