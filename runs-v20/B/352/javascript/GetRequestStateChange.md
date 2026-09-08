## Verdict

exploitable

- cwe_id: CWE-352 (Cross-Site Request Forgery)
- location: `accountRoutes.js:53`, `app.get('/account/delete', requireSession, deleteAccountHandler);`
- confidence: high

## Source

The request is the source: any GET request to `/account/delete` from a browser holding a valid session cookie for the target application. Because it is a simple `GET` navigation (no custom headers, no non-form content type), it can be triggered cross-site with nothing more than an `<img src="...">`, `<a href="...">`, or auto-submitting link embedded on an attacker-controlled page or email - the browser attaches the victim's session cookie automatically. `requireSession` confirms the victim is logged in but does not confirm the request originated from the application.

## Fix

### File: accountRoutes.js

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();
app.use(express.json());
app.use(cookieParser());

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.id,
  cookieName: 'x-csrf-token',
  cookieOptions: { sameSite: 'lax', secure: true },
});

const accounts = new Map();

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'authentication required' });
  }
  next();
}

function deleteAccountHandler(req, res) {
  accounts.delete(req.session.userId);
  res.json({ status: 'deleted' });
}

// Profile and email changes are correctly protected: doubleCsrfProtection
// validates the token on every one of these non-safe requests before the
// handler runs.
app.post('/account/profile', requireSession, doubleCsrfProtection, (req, res) => {
  const account = accounts.get(req.session.userId) || {};
  accounts.set(req.session.userId, { ...account, ...req.body });
  res.json({ status: 'updated' });
});

app.put('/account/email', requireSession, doubleCsrfProtection, (req, res) => {
  const account = accounts.get(req.session.userId) || {};
  accounts.set(req.session.userId, { ...account, email: req.body.email });
  res.json({ status: 'updated' });
});

app.delete('/account', requireSession, doubleCsrfProtection, deleteAccountHandler);

// Convenience link for the "delete my account" confirmation email button.
// The GET route now only renders a confirmation page - it no longer mutates
// state - so it never needs to pass through doubleCsrfProtection. The actual
// deletion happens on the POST below, which is a normal state-changing route
// and goes through requireSession + doubleCsrfProtection like every other
// mutation in this file. This preserves the email link (it still resolves to
// GET /account/delete) but the link itself can no longer trigger the deletion;
// a same-site page load is required to submit the confirmation form.
app.get('/account/delete', requireSession, (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.type('html').send(`
    <form method="POST" action="/account/delete">
      <input type="hidden" name="_csrf" value="${csrfToken}">
      <button type="submit">Confirm account deletion</button>
    </form>
  `);
});

app.post('/account/delete', requireSession, doubleCsrfProtection, deleteAccountHandler);

module.exports = app;
```

## Explanation

The reported sink, `app.get('/account/delete', requireSession, deleteAccountHandler)`, executes the state-changing `deleteAccountHandler` directly from a `GET` route. `doubleCsrfProtection` is configured and correctly applied to every `POST`/`PUT`/`DELETE` route in the file, but CSRF middleware only validates non-safe methods, so this `GET` route bypassed it entirely - any cross-site link or auto-loading resource pointed at it deletes the victim's account. The fix keeps `GET /account/delete` reachable at the same URL (so the existing email button still resolves) but changes what it does: it now renders a same-site confirmation page containing a form, with a freshly minted CSRF token (`generateCsrfToken`, the v4 `csrf-csrf` export - this file already relies on the v4-only `getSessionIdentifier` option, so the same major version's token-generation export applies) embedded as a hidden field. That form submits a `POST` to a new `/account/delete` route, which performs the actual deletion behind the same `requireSession` + `doubleCsrfProtection` chain already used for `/account/profile`, `/account/email`, and `DELETE /account`. An attacker's cross-site request can still land on the GET confirmation page, but cannot forge the token needed to submit the form, so the deletion itself is no longer reachable without a legitimate, same-site form post.

## Behaviour changes

- Clicking the existing email link no longer deletes the account immediately; it now lands on a confirmation page and requires one additional same-site form submission before the account is deleted. This is the intended effect of the fix (an unauthenticated GET can no longer carry a state change) and is called out per the loaded guidance, which requires preserving the link's URL rather than deleting or silently retargeting it.
- A new route, `app.post('/account/delete', ...)`, is added. It reuses the existing `deleteAccountHandler` and the same `requireSession`/`doubleCsrfProtection` middleware already applied to the other mutating routes, so its behavior and response (`{ status: 'deleted' }`) match the original handler exactly - only the verb and the CSRF check are new.
- `generateCsrfToken` is added to the `doubleCsrf(...)` destructure. It is called only to render the confirmation form and produces a per-request token string; it has no effect on any other route.
- No existing route's arguments, middleware order, return values, or error handling were changed. `app.delete('/account', ...)` and the `POST`/`PUT` account routes are untouched.

## Verification

Ran `node --check` against the complete fixed file (copied to a scratch location outside the repo, `csrf-csrf`/`express`/`cookie-parser` not installed in that scratch environment) - passed with no output, confirming the file parses as valid JavaScript. `generateCsrfToken` and `doubleCsrfProtection` are both destructured from the same `doubleCsrf(...)` call already present in the original file, so no new import or package was introduced; `generateCsrfToken` is the name the loaded `cwe/352/javascript/INDEX.md` guidance gives for `csrf-csrf` v4, and this file's existing use of `getSessionIdentifier` (a v4-only required option per that same guidance) confirms v4 is the version in play. `res.type()` and `res.send()` are standard Express `Response` methods already implied by this file's use of `res.json()` from the same object. No test suite ships with this single-file case, so no functional/integration test was run beyond the syntax check.
