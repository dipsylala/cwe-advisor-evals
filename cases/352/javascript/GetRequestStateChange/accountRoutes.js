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
// doubleCsrfProtection is only wired into the POST/PUT/DELETE routes above -
// it never runs on a GET request, so this route inherits none of the CSRF
// checks configured for the rest of this app even though the app's CSRF
// setup itself is correct.
// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
app.get('/account/delete', requireSession, deleteAccountHandler);

module.exports = app;
