## Verdict

- **CWE-352** (Cross-Site Request Forgery) - **exploitable**
- **Location**: `transferRoutes.js:15-21`, the `app.post('/api/transfer', ...)` handler and its guard.
- **Confidence**: high.
- **Library recommendation**: `csrf-csrf` (maintained successor to the deprecated `csurf`), plus `cookie-parser` if not already mounted on the app. The loaded guidance carries no minimum safe version for `csrf-csrf`; resolve the version against SCA/dependency-check tooling before merging, not from this write-up.
- **Assumptions**:
  - The three case files are the full call chain; no `app.js`/bootstrap file was provided. `req.session` is used already, so session middleware is assumed present upstream; `cookie-parser` is assumed either already mounted there or added alongside this fix (`doubleCsrfProtection` requires it to read/write its cookie).
  - `CSRF_SECRET` must be supplied via environment/secret configuration outside this call chain; it is referenced but not defined here, consistent with the guidance's `getSecret` contract.
  - No `package.json` was in scope, so the new `csrf-csrf` dependency is stated in the explanation rather than shown as a manifest diff.

## Source

- **Source**: an attacker-controlled cross-site HTTP request (e.g. an auto-submitting form or `fetch` hosted on another origin) targeting `POST /api/transfer` on a victim's browser that holds an authenticated session cookie for this app.
- **Path**: the browser attaches the session cookie automatically, so `requireSession` (transferRoutes.js:6-11) passes. The only other gate is `allowSameOriginOrMissing(req)` from `csrfOriginPolicy.js`, which compares `Origin`/`Referer` against the expected host but **returns `true` (allow) whenever both headers are absent** - a request that omits both headers, which an attacker's tooling can arrange, passes this check.
- **Sink**: `ledger.scheduleTransfer({ fromUserId, toAccount, amountCents })` in `transferRoutes.js:20-24` (implemented in `transferLedger.js`), which unconditionally queues a fund transfer using `req.session.userId` (the victim) and attacker-supplied `req.body.toAccount` / `req.body.amountCents`. No server-controlled CSRF token is checked anywhere in the chain - the origin check is the sole defence, and it is not a Synchronizer Token.

**Sink contract** (`ledger.scheduleTransfer`):
- Returns: a `transfer` object (`id`, `fromUserId`, `toAccount`, `amountCents`, `queuedAt`), which the route serializes into the `200 { status: 'scheduled', transferId }` response.
- Discards: nothing beyond what it returns.
- Implicit arguments: none - all three fields are passed explicitly.
- Failure behaviour: none observed; it does not validate or throw, so any upstream check has to keep bad requests from reaching it.

## Fix

### File: csrfProtection.js

```javascript
'use strict';

const { doubleCsrf } = require('csrf-csrf');

// CSRF_SECRET must be set in the environment; do not fall back to a hardcoded value.
const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.userId,
  cookieName: '__Host-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    path: '/'
  }
});

module.exports = { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError };
```

### File: transferRoutes.js

```javascript
'use strict';

const { allowSameOriginOrMissing } = require('./csrfOriginPolicy');
const { TransferLedger } = require('./transferLedger');
const { generateCsrfToken, doubleCsrfProtection, invalidCsrfTokenError } = require('./csrfProtection');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function handleCsrfErrors(err, req, res, next) {
  if (err === invalidCsrfTokenError) {
    return res.status(403).json({ error: 'invalid or missing csrf token' });
  }
  return next(err);
}

function registerTransferRoutes(app, ledger = new TransferLedger()) {
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

  app.use(handleCsrfErrors);
}

module.exports = { registerTransferRoutes };
```

## Explanation

The route's only defence against forged requests was `allowSameOriginOrMissing`, an Origin/Referer comparison that fails open when both headers are absent - not a server-controlled authenticity check, so it does not close CWE-352. The fix adds Synchronizer Token Pattern protection with `csrf-csrf`: `csrfProtection.js` configures `doubleCsrf` with `getSessionIdentifier` bound to `req.session.userId` (so a token minted for one session cannot validate another) and a `secure`, `SameSite=Lax`, `__Host`-prefixed cookie. `transferRoutes.js` adds a `GET /api/csrf-token` endpoint (behind `requireSession`) so an authenticated client can obtain a token, applies `doubleCsrfProtection` to `POST /api/transfer` before the handler runs, and adds `handleCsrfErrors` to turn a rejected/missing token into a `403` instead of an unhandled error. The pre-existing Origin/Referer check is left in place unchanged as defence-in-depth, per the guidance ("Validate Origin/Referer headers for additional protection on critical endpoints") - the token check is now the primary control, so its fail-open gap on missing headers no longer matters. `scheduleTransfer`'s contract (arguments, return value, and lack of internal validation) is untouched.

## Behaviour changes

- New route `GET /api/csrf-token` (behind `requireSession`) - did not exist before. Required so a legitimate client has a way to obtain the token; without it no caller could ever satisfy the new check.
- `POST /api/transfer` now requires an `x-csrf-token` header (or `_csrf` body field) matching the token issued for that session; a request that omits or mismatches it now receives `403 { error: 'invalid or missing csrf token' }` instead of proceeding to `allowSameOriginOrMissing`. This is the intended effect of closing the CWE-352 gap: any existing client (browser form, SPA, script) that does not first call `GET /api/csrf-token` and forward the token will start failing and must be updated to do so.
- `doubleCsrfProtection` sets a new `__Host-csrf-token` cookie on responses from `/api/csrf-token` and validates/rotates it on `/api/transfer` - a cookie the client did not receive before.
- `app.use(handleCsrfErrors)` adds an error-handling middleware to `app` after these routes; it intercepts only `invalidCsrfTokenError` and forwards every other error unchanged via `next(err)`, so it does not alter handling of unrelated errors elsewhere in the app.
- New runtime dependency: `csrf-csrf` (and `cookie-parser` if not already present upstream), and a new required environment variable `CSRF_SECRET`.
- `allowSameOriginOrMissing`, `requireSession`, `ledger.scheduleTransfer`, and the success/response shape of `POST /api/transfer` are otherwise unchanged.

**Verification**: `node --check` was run against both new/modified files in isolation (copies outside the case directory) and returned no syntax errors. `csrf-csrf`'s API (`doubleCsrf`, `generateCsrfToken`, `doubleCsrfProtection`, `invalidCsrfTokenError`, `getSessionIdentifier`) was not independently re-verified against an installed copy of the package (none available in this environment); its names are taken directly from the loaded `cwe/352/javascript/INDEX.md` guidance rather than from recall.
