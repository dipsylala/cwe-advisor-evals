## Verdict

CONFIRMED. CWE-352 CSRF vulnerability due to missing session identifier binding in CSRF middleware configuration. The `doubleCsrf()` initialization omits the required `getSessionIdentifier` parameter, causing tokens to be validated only against the secret/cookie pair rather than against the session they were issued for. This allows CSRF tokens to be reused across sessions.

## Source

File: `csrfProtection.js`

The middleware initialization on lines 9-20 constructs a CSRF protection middleware via `doubleCsrf()` but omits the `getSessionIdentifier` configuration parameter. According to `csrf-csrf` v4+ documentation, this parameter is required to bind each generated token to the session it was issued for. Without it, a token generated for one user's session could potentially be validated in a different user's session, breaking the per-session token binding that CSRF protection requires.

## Fix

**Vulnerable code** (csrfProtection.js, lines 9-20):
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

**Fixed code**:
```javascript
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req, res) => req.session.userId,
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    httpOnly: true
  }
});
```

## Explanation

The Synchronizer Token Pattern requires binding CSRF tokens to individual sessions. The `getSessionIdentifier` parameter tells the middleware how to extract the session identifier from each request. By adding `getSessionIdentifier: (req, res) => req.session.userId`, the middleware now:

1. Associates each generated token with the user's session ID (via `req.session.userId`, which is already in use by `requireSession`)
2. On validation, checks not only that the token cryptographically matches the secret, but also that it was issued for the current request's session
3. Prevents token reuse across sessions, closing the CSRF weakness

The fix preserves all existing behavior (cookie settings, secret generation, token format) while adding the critical per-session binding that the middleware was designed to provide.

## Behaviour changes

- CSRF tokens are now bound to the user session they were issued for
- A token cannot be reused in a different user's session
- This is the intended behavior of double-submit CSRF protection and prevents session-crossing token reuse
- No breaking changes to the public API; the middleware continues to work identically from the route handlers' perspective
