## Verdict

exploitable

## Source

**Location**: evals/cases/352/javascript/MultiFileTransferCsrf/transferRoutes.js:15

**Source**: Untrusted request data in `req.body.toAccount` and `req.body.amountCents` supplied by HTTP POST request

**Sink**: `app.post('/api/transfer', ...)` state-changing endpoint

**Data Flow**: Attacker-controlled request body parameters flow directly from the HTTP handler into `ledger.scheduleTransfer()`, which executes a state-changing operation (financial transfer). The current code relies only on Origin/Referer header validation via `allowSameOriginOrMissing()`, which is insufficient protection against CSRF attacks because:
1. Browsers may omit Origin/Referer headers in legitimate requests
2. The code allows missing headers (`if (origin && !origin.startsWith(...))` returns true when origin is falsy)
3. Simple POST requests bypass CORS preflight and can be issued from any cross-origin site with automatic session cookie inclusion
4. No cryptographic CSRF token is used to verify request authenticity

## Fix

**Vulnerable Code** (transferRoutes.js:13-28):
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

**Fixed Code** (requires `doubleCsrfProtection` imported from `csrf-csrf`):
```javascript
function registerTransferRoutes(app, ledger = new TransferLedger(), doubleCsrfProtection) {
  app.post('/api/transfer', requireSession, doubleCsrfProtection, (req, res) => {
    const transfer = ledger.scheduleTransfer({
      fromUserId: req.session.userId,
      toAccount: req.body.toAccount,
      amountCents: Number(req.body.amountCents)
    });

    return res.json({ status: 'scheduled', transferId: transfer.id });
  });
}
```

**Library Recommendation**: Use `csrf-csrf` (NPM package). Install with `npm install csrf-csrf cookie-parser`. The minimum safe version should be verified against current advisory data, as the loaded guidance does not specify a version floor. Ensure `getSessionIdentifier` is configured in `doubleCsrf()` options so tokens are bound to individual sessions.

## Explanation

The fix adds the `doubleCsrfProtection` middleware to the state-changing endpoint. This middleware validates an encrypted CSRF token that must be present in the request (either as a custom `x-csrf-token` header or `_csrf` body field). The token is cryptographically bound to the user's session via the `getSessionIdentifier` callback, preventing attackers from forging valid tokens. The middleware automatically rejects requests lacking a valid token with a 403 response, eliminating the CSRF vulnerability. The Origin/Referer header check is removed because CSRF token validation is the primary defence and is cryptographically stronger than header-based checks. Token generation happens on the client side (via a GET endpoint or inline in page load) where `generateCsrfToken(req, res)` is called, and the token must be included in every POST request to this endpoint.

## Behaviour changes

1. **Middleware addition**: `doubleCsrfProtection` now intercepts the request before the handler runs. This adds approximately 1-2ms per request for token validation.
2. **Removed header validation**: The `allowSameOriginOrMissing()` call is no longer present. Requests without Origin/Referer headers now succeed if the CSRF token is valid (previously allowed unconditionally). This is a security improvement and not a regression.
3. **Token requirement**: All requests to this endpoint must now include a valid CSRF token in the `x-csrf-token` header (AJAX) or `_csrf` body field (forms). Requests lacking the token will receive a 403 response. Legitimate clients (web forms and AJAX handlers) must be updated to obtain and send the token with each request.
4. **Session binding**: Tokens are now bound to individual session identifiers. A token from one user's session cannot be reused in another user's session, and tokens are invalidated if the session identifier changes (e.g., at login).
5. **No change to response contract**: The endpoint still returns the same JSON response on success. Error responses now include CSRF validation errors (403 status) in addition to existing error cases (401 for missing session).
