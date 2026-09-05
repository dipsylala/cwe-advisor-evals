## Verdict

Exploitable. The GET endpoint at line 53 directly performs account deletion without CSRF protection. State-changing operations must not be reachable via GET; this endpoint is vulnerable to cross-site request forgery through simple requests (image tags, redirects, etc.) that cannot include the CSRF token.

## Source

Unauthenticated attacker crafting a cross-site request (e.g., `<img src="https://target.com/account/delete">`) that leverages an authenticated user's session to trigger the deletion.

## Fix

**Vulnerable code (line 53):**
```javascript
// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
app.get('/account/delete', requireSession, deleteAccountHandler);
```

**Fixed code:**
Extract `generateCsrfToken` from the `doubleCsrf` return value (line 9), then replace the GET route and add a protected POST route:

```javascript
const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.id,
  cookieName: 'x-csrf-token',
  cookieOptions: { sameSite: 'lax', secure: true },
});

// ... existing POST and PUT routes ...

// GET /account/delete renders a confirmation page with a CSRF token.
// The form inside submits to a protected POST route.
app.get('/account/delete', requireSession, (req, res) => {
  const token = generateCsrfToken(req, res);
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>Confirm Account Deletion</title></head>
      <body>
        <h1>Delete Account</h1>
        <p>This action cannot be undone.</p>
        <form method="POST" action="/account/delete-confirm">
          <input type="hidden" name="_csrf" value="${token}">
          <button type="submit">Confirm Delete</button>
          <a href="/account">Cancel</a>
        </form>
      </body>
    </html>
  `);
});

// POST route with CSRF protection performs the actual deletion.
app.post('/account/delete-confirm', requireSession, doubleCsrfProtection, deleteAccountHandler);
```

## Explanation

The fix separates the confirmation step (GET) from the state-changing operation (POST). The GET endpoint now renders an HTML form containing a server-generated CSRF token bound to the user's session. The form's POST action points to `/account/delete-confirm`, which applies the `doubleCsrfProtection` middleware before calling the handler. This eliminates the vulnerability because:
1. Cross-site requests cannot include the custom CSRF token in the form's hidden field
2. State changes are no longer reachable via GET, preventing simple-request exploitation
3. The CSRF token validates that the request originated from the legitimate application

The token is generated fresh on each confirmation-page load and expires with the session, preventing token fixation or replay attacks.

## Behaviour changes

- GET `/account/delete` now returns an HTML confirmation page (status 200 with `Content-Type: text/html`) instead of deleting the account. This is a security-required behaviour change: the endpoint no longer accepts simple requests that can cross site boundaries.
- A new POST endpoint `/account/delete-confirm` is introduced to accept deletion requests, protected by CSRF middleware. Clients must parse the confirmation HTML form and submit it as a POST to proceed with deletion.
- The `generateCsrfToken(req, res)` call generates a session-bound token fresh on each confirmation-page load; the token is included in the HTML form and validated by the POST route's middleware before execution.
- Existing links (email buttons, settings-page anchors) that point to `GET /account/delete` now land on a confirmation page rather than triggering immediate deletion, which is a required UX change that prevents CSRF but breaks direct-link assumptions. No redirect is used; the user must actively confirm via the form.
