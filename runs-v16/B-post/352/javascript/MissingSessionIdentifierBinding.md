## Verdict

exploitable

## Source

User-supplied POST request to `/api/account/password` endpoint. The request is expected to carry a CSRF token in the `x-csrf-token` cookie or request header, but the token validation does not bind it to the current user's session.

## Fix

**Vulnerable code (csrfProtection.js, lines 9-20):**

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

**Fixed code:**

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

The csrf-csrf library v4+ requires the `getSessionIdentifier` parameter to bind each CSRF token to the session that issued it. Without this function, the token validation only checks the token against the secret and cookie pair, never verifying which session the token belongs to. This allows a token generated for User A's session to be replayed in User B's session, violating the session-identifier-binding requirement of proper CSRF protection. Adding `getSessionIdentifier: (req) => req.session.userId` ensures that the generated token is cryptographically tied to a specific user's session, and the middleware rejects any attempt to use that token in a different user's authenticated context.

## Behaviour changes

The doubleCsrf configuration now extracts and validates the session identifier from every request. This is a required security change with no functional side effects: the middleware still validates tokens with the same call signature and failure modes, but now rejects cross-session token reuse. Existing clients that follow the normal token fetch → form submission flow are unaffected. The only change in behaviour is that a token minted in one session is no longer valid in another, which is the intended defence-in-depth mechanism.
