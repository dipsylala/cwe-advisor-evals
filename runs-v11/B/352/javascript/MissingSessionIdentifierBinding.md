## Verdict

Exploitable. Without session identifier binding, a CSRF token generated in one user's session is accepted as valid in any other user's session, allowing cross-session token reuse attacks.

## Source

CSRF protection initialization in csrfProtection.js, lines 9–20: `doubleCsrf()` call omits the `getSessionIdentifier` parameter. The double-submit token is validated only against the secret/cookie pair, never against the session that issued it.

## Fix

**Vulnerable code** (csrfProtection.js, lines 9–20):
```javascript
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
```

**Fixed code** (csrfProtection.js, lines 9–20):
```javascript
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.userId,
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    httpOnly: true
  }
});
```

## Explanation

The fix adds `getSessionIdentifier: (req) => req.session.userId` to the `doubleCsrf()` configuration. This parameter is required as of csrf-csrf v4 and binds each generated token to a specific session. Without it, the middleware validates tokens only against the secret, accepting a token from any session. With the fix, the middleware verifies that the token was issued for the current user's session, rejecting cross-session token reuse. The `req.session.userId` value is already set by the `requireSession` middleware in accountRoutes.js (line 7), ensuring every protected route has a valid session identifier to bind to.

## Behaviour changes

The fixed middleware adds a session identifier check to token validation. A token generated for session A will now be rejected if presented in session B, even if both sessions are authenticated. This is the correct behavior: it prevents an attacker from stealing a CSRF token from one user and using it to attack another, closing the cross-session reuse gap. No other contract changes—the middleware still validates only on POST/PUT/DELETE, still returns 403 on invalid tokens, and the token format and generation remain unchanged.
