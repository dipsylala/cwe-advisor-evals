## Verdict

Confirmed. `GET /account/delete` performs a state-changing action (account deletion) without CSRF protection.

## Source

`E:/Github/cwe-advisor/evals/cases/352/javascript/GetRequestStateChange/accountRoutes.js`, line 53:

```
app.get('/account/delete', requireSession, deleteAccountHandler);
```

The route is reached by a plain browser navigation (the "delete my account" link in a confirmation email). Because it is a `GET` request, `cookie-parser` still attaches the session cookie automatically, so `requireSession` passes for any logged-in victim who follows the link. The route never passes through `doubleCsrfProtection`, and by design the `csrf-csrf` middleware's default `ignoredMethods` skips `GET`, `HEAD`, and `OPTIONS` - so simply routing this handler through `doubleCsrfProtection` as-is would not add any real protection, since the middleware would still treat `GET` as an ignored, unchecked method. An attacker can host an `<img src="https://victim-app/account/delete">` or a redirect and delete any visiting authenticated user's account with no interaction beyond viewing a page.

## Fix

### File: accountRoutes.js
```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();
app.use(express.json());
app.use(cookieParser());

const { doubleCsrfProtection } = doubleCsrf({
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

// The "delete my account" confirmation email now links to a page that
// renders a confirmation form instead of triggering the deletion directly.
// The GET route only serves that form - it performs no state change, so it
// needs no CSRF token - and the form's submission goes through the
// protected POST route below, exactly like the other mutating routes in
// this file.
app.get('/account/delete', requireSession, (req, res) => {
  const token = doubleCsrfProtection.generateToken
    ? doubleCsrfProtection.generateToken(req, res)
    : req.csrfToken();
  res.send(`
    <form method="POST" action="/account/delete">
      <input type="hidden" name="csrf_token" value="${token}">
      <button type="submit">Confirm account deletion</button>
    </form>
  `);
});

app.post('/account/delete', requireSession, doubleCsrfProtection, deleteAccountHandler);

module.exports = app;
```

## Explanation

The vulnerability is that a destructive operation was reachable through a safe HTTP method (`GET`), which browsers issue on ordinary navigation, image loads, and redirects with no user intent to submit anything - and CSRF middleware such as `csrf-csrf` is designed to ignore safe methods by default, so it offers no protection there regardless of whether it is attached to the route.

The fix does not try to force CSRF validation onto the `GET` route. Instead it moves the actual deletion behind a `POST /account/delete` route that is wired into `doubleCsrfProtection` exactly like the existing `POST`/`PUT`/`DELETE` routes in this file, preserving the app's established pattern. The `GET /account/delete` route that the email link points to is repurposed into a harmless confirmation page: it performs no mutation, so it needs no CSRF check, and it hands the user a form whose submission (a real `POST`) carries the CSRF token and goes through the same validated path as every other state-changing action in the app. This closes the gap without weakening or duplicating the CSRF configuration, and it keeps the "click a link in an email" user flow intact by adding one confirmation step, which is the standard mitigation for a state change previously triggered by simple navigation.
