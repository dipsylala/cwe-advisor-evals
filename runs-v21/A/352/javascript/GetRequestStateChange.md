## Verdict

The finding is valid. Line 53 exposes a state-changing endpoint without CSRF protection, creating a classic CWE-352 vulnerability.

## Source

Line 53: `app.get('/account/delete', requireSession, deleteAccountHandler);`

The `/account/delete` GET endpoint calls `deleteAccountHandler` (lines 25–28), which modifies application state by deleting an account. Unlike the POST/PUT/DELETE endpoints protected by `doubleCsrfProtection` (lines 33, 39, 45), this GET route lacks CSRF protection entirely. Attackers can trigger account deletion by inducing an authenticated user to visit a malicious page containing a simple link or image referencing the endpoint URL.

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
// doubleCsrfProtection is now wired into all state-changing routes,
// including this GET request, to prevent CSRF attacks.
app.get('/account/delete', requireSession, doubleCsrfProtection, deleteAccountHandler);

module.exports = app;
```

## Explanation

The fix adds `doubleCsrfProtection` middleware to line 53, between `requireSession` and `deleteAccountHandler`. This ensures the CSRF token is validated before the handler executes, preventing CSRF attacks.

State-changing operations must validate a CSRF token regardless of HTTP method. The middleware checks that the request carries a valid token (passed in the request body, header, or URL parameter depending on client implementation) that matches the user's session, ensuring the action originated from an authorized interaction with the application itself, not from an attacker-controlled page.

