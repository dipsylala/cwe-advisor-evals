## Verdict

The password change endpoint at line 27 lacks proper session-identifier binding for CSRF protection. While the `doubleCsrfProtection` middleware is applied, it does not bind the CSRF token to the session ID, allowing CSRF tokens to be valid across different sessions.

## Source

```javascript
// Line 27-30: Password change endpoint
app.post('/api/account/password', requireSession, doubleCsrfProtection, (req, res) => {
    accounts.updatePassword(req.session.userId, req.body.newPassword);
    return res.json({ status: 'updated' });
});
```

The vulnerability is that `doubleCsrfProtection` validates the CSRF token independently of the session identifier. An attacker could craft a valid token and inject it into a victim's request without the token being tied to that specific session.

## Fix

Replace line 27-30 with:

```javascript
app.post('/api/account/password', requireSession, (req, res) => {
    // Validate CSRF token is bound to the session
    const tokenFromSession = req.session.csrfToken;
    const tokenFromRequest = req.body._csrf || req.headers['x-csrf-token'];
    
    if (!tokenFromSession || tokenFromSession !== tokenFromRequest) {
        return res.status(403).json({ error: 'CSRF validation failed' });
    }
    
    accounts.updatePassword(req.session.userId, req.body.newPassword);
    return res.json({ status: 'updated' });
});
```

Additionally, update the `/api/account/csrf-token` endpoint to store the token in the session:

```javascript
app.get('/api/account/csrf-token', requireSession, (req, res) => {
    const token = generateCsrfToken(req, res);
    req.session.csrfToken = token;
    return res.json({ csrfToken: token });
});
```

## Explanation

The fix binds the CSRF token to the session by:

1. Storing the token in `req.session.csrfToken` when it is generated, creating an explicit binding to the session identifier (which is stored in the session cookie).
2. Validating on the sensitive POST route that the submitted CSRF token (`req.body._csrf` or the `x-csrf-token` header) matches the token stored in the session.
3. Removing the session-agnostic `doubleCsrfProtection` middleware from this critical endpoint and replacing it with session-bound validation.

This ensures that a CSRF token is only valid for the specific user session it was issued to, preventing token reuse across different sessions and mitigating CSRF attacks that attempt to forge or steal tokens.
