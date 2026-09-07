## Verdict

The code performs a state-changing operation (account deletion) via an unprotected GET request. This violates CWE-352 remediation by making the endpoint vulnerable to cross-site request forgery through link-based attacks. The GET request also violates HTTP semantics, since safe methods should not modify server state.

## Source

Line 53 of accountRoutes.js defines a GET endpoint that invokes deleteAccountHandler without CSRF protection:

```javascript
app.get('/account/delete', requireSession, deleteAccountHandler);
```

The deleteAccountHandler (lines 25–28) removes the user's account from the server state. While requireSession checks authentication, it does not prevent cross-site forging of this dangerous request.

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

// Convenience link for the "delete my account" confirmation email button.
// Changed from GET to POST to comply with HTTP semantics (state-changing
// operations should not use safe methods) and to enable CSRF protection.
// doubleCsrfProtection validates the CSRF token before the handler runs.
app.post('/account/delete', requireSession, doubleCsrfProtection, deleteAccountHandler);

module.exports = app;
```

## Explanation

The fix changes the endpoint from GET to POST and adds the `doubleCsrfProtection` middleware. This achieves two goals:

1. **HTTP Compliance**: POST is the correct method for state-changing operations. GET requests should be idempotent and safe; they must not modify server state.

2. **CSRF Protection**: The `doubleCsrfProtection` middleware now validates the CSRF token before deleteAccountHandler executes, preventing cross-site forgery. The token must be present in the request (via cookie and body/header), making it impossible for an attacker to forge the deletion via a simple link or form submission from a malicious site.

Clients must now submit a POST request with a valid CSRF token to delete an account. This is the same protective pattern applied to the profile and email endpoints in this file.
