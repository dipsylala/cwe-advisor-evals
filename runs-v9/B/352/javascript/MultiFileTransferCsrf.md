## Verdict

CWE-352 (Cross-Site Request Forgery) - **exploitable**. Confidence: high.

`POST /api/transfer` (`transferRoutes.js:15`) is a state-changing, session-cookie-authenticated endpoint (`requireSession` only checks that `req.session.userId` exists) with no CSRF token. Its only anti-CSRF control, `allowSameOriginOrMissing` (`csrfOriginPolicy.js`), fails open in two independent ways:

- **Missing-header bypass**: when both `Origin` and `Referer` are absent, `origin` is falsy, the `if (origin && ...)` guard short-circuits, and the function returns `true` (allowed) at line 11. An attacker page can omit both headers (e.g. `<meta name="referrer" content="no-referrer">` plus a request path that doesn't set `Origin`) and sail through.
- **Prefix-match bypass**: the check is `origin.startsWith(expected)`, not an exact match. `expected` is `"https://victim.example.com"`. An attacker-controlled origin `"https://victim.example.com.attacker.net"` satisfies `startsWith("https://victim.example.com")` and is accepted as same-origin.

Either gap alone is sufficient to forge the request from a cross-site attacker page while the victim's session cookie is attached automatically by the browser.

## Source

- **Source**: a cross-site page controlled by an attacker, submitted through the victim's browser using the victim's authenticated session cookie. Origin/Referer headers are either withheld or crafted to a suffix-matching hostname.
- **Sink**: `app.post('/api/transfer', requireSession, (req, res) => { ... ledger.scheduleTransfer(...) ... })` in `transferRoutes.js:15-27`.
- **Path**: request -> `requireSession` (auth-only, no CSRF relevance) -> `allowSameOriginOrMissing` (the sole, bypassable CSRF check) -> `ledger.scheduleTransfer({ fromUserId: req.session.userId, toAccount: req.body.toAccount, amountCents: Number(req.body.amountCents) })` in `transferLedger.js`, which records the transfer unconditionally once it reaches that point. No synchronizer/double-submit token is checked anywhere in the chain.

## Fix

**Library recommendation**: `csrf-csrf` (the maintained successor to the deprecated `csurf`, per the loaded JavaScript CSRF guidance). The guidance does not carry a minimum safe version, so none is asserted here - resolve and pin the version via SCA/dependency-check tooling before merging. Add to `package.json`:

```
npm install csrf-csrf cookie-parser
```

(Requires `cookie-parser` mounted at the app level before these routes, e.g. `app.use(cookieParser())` - not shown here as it lives outside the three files in scope.)

**Vulnerable code** (`transferRoutes.js`):

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

**Fixed code** - new file `csrfProtection.js` (single, shared `doubleCsrf` instance so the same secret/session binding is used everywhere it's needed):

```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');

const { doubleCsrfProtection, generateCsrfToken, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.userId,
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    httpOnly: true
  }
});

module.exports = { doubleCsrfProtection, generateCsrfToken, invalidCsrfTokenError };
```

`transferRoutes.js`:

```javascript
'use strict';

const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
const { TransferLedger } = require('./transferLedger');
const { doubleCsrfProtection, generateCsrfToken, invalidCsrfTokenError } = require('./csrfProtection');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function csrfErrorHandler(err, req, res, next) {
  if (err === invalidCsrfTokenError) {
    return res.status(403).json({ error: 'invalid csrf token' });
  }
  return next(err);
}

function registerTransferRoutes(app, ledger = new TransferLedger()) {
  // Lets an already-authenticated client fetch a token to submit with the transfer request.
  app.get('/api/csrf-token', requireSession, (req, res) => {
    return res.json({ csrfToken: generateCsrfToken(req, res) });
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

  app.use(csrfErrorHandler);
}

module.exports = { registerTransferRoutes };
```

## Explanation

`doubleCsrfProtection` is inserted into the `/api/transfer` chain after `requireSession` (so `req.session.userId` is guaranteed to exist for `getSessionIdentifier`) and before the handler, requiring a server-issued, session-bound token on every request - the double-submit/synchronizer pattern the general and JavaScript CWE-352 guidance both call for as the primary defence. The token is minted per session by `generateCsrfToken` and served from a new `GET /api/csrf-token` endpoint (itself gated by `requireSession`, so an attacker cannot mint a token for a session they don't control) so a legitimate client can fetch it and echo it back in the `x-csrf-token` header, per `csrf-csrf`'s default. A cross-site attacker page has no way to read that token (same-origin policy blocks the response body) and so cannot reproduce it, which closes both bypasses in `allowSameOriginOrMissing` - the check is left in place unchanged as defence-in-depth, per the guidance's "additional protection" framing, not as the sole control. `csrfErrorHandler` turns a failed/missing-token error into an explicit `403` instead of an unhandled exception, matching the sink's existing error-response shape (`res.status(...).json({ error: ... })`).

Assumption: `getSecret` reads a `CSRF_SECRET` environment variable and app-level `cookie-parser` middleware is mounted upstream of these routes - neither is visible in the three files in scope, so this is the standard `csrf-csrf` wiring rather than something verified against this codebase's actual app bootstrap. Confidence is lowered accordingly on the wiring detail only, not on the vulnerability finding itself.

## Behaviour changes

- **New endpoint added**: `GET /api/csrf-token`, gated by `requireSession`. Necessary companion to the token-based fix - a client cannot supply a token it was never issued. It performs no state change and does not exist in the original code.
- **New failure mode**: a request to `POST /api/transfer` with a missing or invalid `x-csrf-token` header now receives `403 {"error": "invalid csrf token"}` via `csrfErrorHandler`, where the original code would have proceeded straight to `ledger.scheduleTransfer`. This is the fix itself, not incidental.
- **Middleware ordering**: `doubleCsrfProtection` now runs before the existing `allowSameOriginOrMissing` check inside the handler. The origin check's behaviour and response body (`403 {"error": "cross-site request rejected"}`) are unchanged; a request now has to clear both checks instead of one.
- **New app-level error middleware**: `app.use(csrfErrorHandler)` is registered inside `registerTransferRoutes`. It only reports invalid-CSRF errors and forwards everything else via `next(err)`, so it does not change handling of unrelated errors from other routes - but if this app composes multiple route modules, an error-handling middleware is normally registered once, after every route is mounted, rather than per-module; flagging this as a wiring detail to confirm against the real `app.js`, which is outside the three files in scope.
- **No change** to `TransferLedger.scheduleTransfer`'s signature, return value, or the success-path response shape of `/api/transfer`.
