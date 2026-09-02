'use strict';

const { doubleCsrf } = require('csrf-csrf');

// csrf-csrf v4+ requires getSessionIdentifier to bind each generated token to
// the session it was issued for. It is omitted here, so the double-submit
// token is validated purely against the secret/cookie pair and never checked
// against which session presented it.
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    httpOnly: true
  }
});

module.exports = { generateCsrfToken, doubleCsrfProtection };
