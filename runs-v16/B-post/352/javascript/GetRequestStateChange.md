## Verdict

Exploitable

## Source

HTTP GET request to the `/account/delete` endpoint, initiated by an authenticated user following a cross-site link or clicking an email button.

## Fix

**Vulnerable code (line 53):**
```javascript
app.get('/account/delete', requireSession, deleteAccountHandler);
```

**Fixed code:**
```javascript
// Separate the confirmation page (safe GET) from the state-changing deletion (protected POST).
// The GET route now renders a confirmation form instead of deleting directly.
app.get('/account/delete', requireSession, (req, res) => {
  // Generate a fresh CSRF token for this session to embed in the confirmation form.
  const token = generateCsrfToken(req, res);
  res.send(`
    <html>
      <body>
        <h1>Confirm Account Deletion</h1>
        <p>Are you sure you want to delete your account? This action cannot be undone.</p>
        <form method="POST" action="/account/delete-confirm">
          <input type="hidden" name="_csrf" value="${token}" />
          <button type="submit">Delete My Account</button>
          <button type="button" onclick="window.history.back()">Cancel</button>
        </form>
      </body>
    </html>
  `);
});

// The actual deletion is now a POST route protected by CSRF middleware.
app.post('/account/delete-confirm', requireSession, doubleCsrfProtection, deleteAccountHandler);
```

## Explanation

The vulnerability occurs because GET requests bypass the `doubleCsrfProtection` middleware entirely (middleware only protects POST/PUT/DELETE). An attacker can trick an authenticated user into clicking a link to `/account/delete`, which directly calls `deleteAccountHandler` without any token verification. The fix separates concerns: the GET route now renders a confirmation page with an embedded CSRF token in a form, and the actual deletion happens via a POST request to a new `/account/delete-confirm` route protected by `doubleCsrfProtection`. This ensures that state-changing operations (account deletion) require both a valid CSRF token and an explicit form submission, preventing cross-site attacks. The user retains the ability to delete their account via email or link by following a multi-step confirmation flow rather than a direct action.

## Behaviour changes

- **New GET route behaviour**: `/account/delete` now returns HTML (a confirmation form) instead of JSON and performs no deletion. Existing email links now land on a confirmation page instead of deleting immediately.
- **New POST route created**: `/account/delete-confirm` performs the actual deletion and is protected by `doubleCsrfProtection`. This route requires the CSRF token from the confirmation form.
- **Token generation required**: The GET handler calls `generateCsrfToken(req, res)` to inject a fresh token into the form. This function is already provided by the `csrf-csrf` library's `doubleCsrf()` setup and is the mechanism documented in the language guidance (Step 6 of the remediation steps).
- **Response type change**: The confirmation page returns HTML; the actual deletion (POST) still returns the existing JSON response `{ status: 'deleted' }` from `deleteAccountHandler`.
- **Session binding**: Each CSRF token is bound to the user's session via the `getSessionIdentifier` function already configured in the `doubleCsrf()` setup, so tokens cannot be replayed across sessions.
