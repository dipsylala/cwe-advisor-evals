## Verdict

CONFIRMED. The GET route at line 53 directly performs a state-changing operation (account deletion) without any CSRF token validation. GET requests bypass the CSRF middleware entirely, allowing an attacker to craft a malicious link that forces an authenticated user to delete their own account.

## Source

**File**: `accountRoutes.js` line 53

```javascript
app.get('/account/delete', requireSession, deleteAccountHandler);
```

**Sink**: The `app.get()` handler invokes `deleteAccountHandler`, which calls `accounts.delete(req.session.userId)` - a state-changing operation that lacks CSRF protection.

**Data flow**: An attacker-controlled URL (e.g., in an email, ad, or malicious website) can reach an authenticated user. When the user visits the link, the GET request is processed without CSRF token validation, and the account is deleted immediately.

**Why CSRF middleware does not protect this route**: Express CSRF middleware (including `doubleCsrfProtection` from `csrf-csrf`) only validates non-safe methods (POST, PUT, DELETE, PATCH). GET requests bypass the middleware entirely by design, so a state change reachable by GET remains unprotected regardless of framework configuration.

## Fix

### File: accountRoutes.js

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();
app.use(express.json());
app.use(cookieParser());

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
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

// Render a confirmation page for account deletion. The form on this page
// posts the CSRF token to /account/delete, triggering the state-changing
// operation only after the user explicitly confirms.
app.get('/account/delete', requireSession, (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Delete Account</title>
    </head>
    <body>
      <h1>Delete Account</h1>
      <p>Are you sure you want to delete your account? This action cannot be undone.</p>
      <form method="POST" action="/account/delete">
        <input type="hidden" name="_csrf" value="${csrfToken.replace(/"/g, '&quot;')}">
        <button type="submit">Delete My Account</button>
        <a href="/">Cancel</a>
      </form>
    </body>
    </html>
  `;
  res.send(html);
});

// Process account deletion from the confirmation form with CSRF protection
app.post('/account/delete', requireSession, doubleCsrfProtection, deleteAccountHandler);

module.exports = app;
```

## Explanation

The vulnerability arose because the GET `/account/delete` route performed account deletion directly, bypassing CSRF middleware which only protects non-safe methods. The fix moves the state-changing operation from GET to POST and changes the GET route to render an HTML confirmation page.

**Changes made**:
1. **GET `/account/delete`** (line 53): Changed from directly calling `deleteAccountHandler` to rendering a confirmation page that includes an HTML form. The form is generated with a fresh CSRF token via `generateCsrfToken(req, res)`, bound to the user's session and embedded in a hidden input field named `_csrf`.
2. **POST `/account/delete`** (new route after line 53): Added a new POST route that receives the form submission, validates the CSRF token via `doubleCsrfProtection` middleware, and only then calls `deleteAccountHandler` to perform the deletion.

**Why this closes the vulnerability**:
- An attacker can still craft a link to GET `/account/delete`, but that link now serves an HTML confirmation page instead of deleting the account.
- The account deletion only happens via POST with a valid CSRF token.
- The CSRF token is generated server-side, bound to the user's session (via `getSessionIdentifier`), and verified by the middleware before the handler runs.
- An attacker cannot forge the token without first fetching the confirmation page as that authenticated user, which defeats the cross-site attack.

**Preserved behavior**:
- The DELETE `/account` route remains unchanged for API clients that submit the CSRF token via the `x-csrf-token` header.
- Existing links to `/account/delete` (email buttons, settings pages) continue to work, but now require explicit user confirmation instead of performing the action immediately.
- All other routes and middleware behavior unchanged.

## Behaviour changes

- **GET `/account/delete`**: Now returns an HTML confirmation page (HTTP 200) instead of deleting the account and returning JSON (HTTP 200).
- **New endpoint POST `/account/delete`**: Accepts form submissions with CSRF token and performs account deletion.
- **User experience**: When a user follows a link to delete their account, they now see a confirmation page they must explicitly approve via button click before the deletion occurs. This is a security improvement that also provides better UX by preventing accidental deletions from misclicked links.
- **Attackers**: Cross-site attacks via simple GET requests are now blocked. An attacker would need to trick the victim into visiting the GET page, reading and parsing the HTML, submitting a form, and confirming the action - defeating the automatic exploitation that CSRF enables.
