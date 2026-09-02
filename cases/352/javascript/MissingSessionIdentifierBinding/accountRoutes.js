'use strict';

const { generateCsrfToken, doubleCsrfProtection } = require('./csrfProtection');
const { AccountStore } = require('./accountStore');

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'login required' });
  }
  return next();
}

function registerAccountRoutes(app, accounts = new AccountStore()) {
  // SPA clients fetch a token before submitting the change-email or
  // change-password forms below.
  app.get('/api/account/csrf-token', requireSession, (req, res) => {
    const token = generateCsrfToken(req, res);
    return res.json({ csrfToken: token });
  });

  app.post('/api/account/email', requireSession, doubleCsrfProtection, (req, res) => {
    accounts.updateEmail(req.session.userId, req.body.email);
    return res.json({ status: 'updated' });
  });

  // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
  app.post('/api/account/password', requireSession, doubleCsrfProtection, (req, res) => {
    accounts.updatePassword(req.session.userId, req.body.newPassword);
    return res.json({ status: 'updated' });
  });
}

module.exports = { registerAccountRoutes };
