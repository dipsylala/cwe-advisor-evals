## Verdict

Confirmed. The `POST /api/account/password` route (and its sibling `POST /api/account/email`) authenticates the caller and runs the double-submit CSRF check, but neither the token-issuing route nor the state-changing routes tie the CSRF token to the session that requested it. A CSRF token/cookie pair minted for one session is never checked against the session presenting it on the write request, so a token obtained under one session context can be replayed against a different session for the same or another authenticated user, defeating the CSRF defense at the point that matters: the sensitive password-change sink.

## Source

- Untrusted trigger: a cross-site request (the classic CSRF vector - an attacker-hosted page or email link that causes the victim's browser to submit `POST /api/account/password`).
- Session/session identifier: `req.session` / `req.sessionID`, established by the (external) session middleware and read via `requireSession` at `accountRoutes.js:6-11`.
- CSRF token issuance: `app.get('/api/account/csrf-token', ...)` at `accountRoutes.js:16-19`, which calls `generateCsrfToken(req, res)` but records no association between the issued token and the session that requested it.
- Sink: `accounts.updatePassword(req.session.userId, req.body.newPassword)` at `accountRoutes.js:28`, reached after `requireSession` and `doubleCsrfProtection` but with no check that the CSRF credential actually belongs to `req.session`.

## Fix

### File: accountRoutes.js
```javascript
'use strict';

const { generateCsrfToken, doubleCsrfProtection } = require('./csrfProtection');
const { AccountStore } = require('./accountStore');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

// Binds an issued CSRF token to the session that requested it. Without
// this, a CSRF token/cookie pair that validates the double-submit check
// says nothing about *which* session it was minted for, so a token
// obtained under one session can be replayed against a different
// session's state-changing requests. Tying issuance and use to
// req.sessionID closes that gap.
function requireCsrfBoundToSession(req, res, next) {
  if (!req.session || req.session.csrfSessionId !== req.sessionID) {
    return res.status(403).json({ error: 'csrf token not valid for this session' });
  }
  return next();
}

function registerAccountRoutes(app, accounts = new AccountStore()) {
  // SPA clients fetch a token before submitting the change-email or
  // change-password forms below.
  app.get('/api/account/csrf-token', requireSession, (req, res) => {
    const token = generateCsrfToken(req, res);
    req.session.csrfSessionId = req.sessionID;
    return res.json({ csrfToken: token });
  });

  app.post(
    '/api/account/email',
    requireSession,
    doubleCsrfProtection,
    requireCsrfBoundToSession,
    (req, res) => {
      accounts.updateEmail(req.session.userId, req.body.email);
      return res.json({ status: 'updated' });
    }
  );

  app.post(
    '/api/account/password',
    requireSession,
    doubleCsrfProtection,
    requireCsrfBoundToSession,
    (req, res) => {
      accounts.updatePassword(req.session.userId, req.body.newPassword);
      return res.json({ status: 'updated' });
    }
  );
}

module.exports = { registerAccountRoutes };
```

## Explanation

`doubleCsrfProtection` proves that the request carries a token/cookie pair that matches by the double-submit rule, but that rule alone does not prove the pair was issued to the session now presenting it. The fix closes that gap without touching `csrfProtection.js`'s token mechanics: at issuance, `req.session.csrfSessionId = req.sessionID` records which session the token belongs to, using `req.sessionID` (the stable per-session identifier the session middleware assigns) rather than the application-level `req.session.userId`, so the binding holds even across multiple concurrent sessions for the same user. `requireCsrfBoundToSession` then runs after `doubleCsrfProtection` on both state-changing routes and rejects with 403 unless the current request's session is the one the token was minted for. This applies the same binding to `POST /api/account/email` as to the flagged `POST /api/account/password` route, since both share the identical gap and a fix that closed it on only one would leave the other exploitable. The change is additive - it does not alter `generateCsrfToken`'s or `doubleCsrfProtection`'s existing behavior or call signature, so it composes with whatever double-submit mechanism they already implement.
