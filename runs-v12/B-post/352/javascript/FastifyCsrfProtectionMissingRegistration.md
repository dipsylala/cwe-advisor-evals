## Verdict

CONFIRMED. The POST endpoint at line 39 performs state-changing operations (updating account settings) with only session-cookie authentication, without CSRF token validation. An attacker can forge a cross-site request that an authenticated user's browser will automatically supply credentials for, allowing unauthorized account modifications.

## Source

POST request from an attacker-controlled website, sent to the legitimate application while the user is authenticated. The browser automatically includes the session cookie (because it is set with `HttpOnly`, `Secure`, and `SameSite=Lax`) due to trust in the session mechanism.

## Fix

**Step 1: Register `@fastify/csrf-protection` plugin**

Add this after session registration (line 16):

```javascript
fastify.register(require('@fastify/csrf-protection'))
```

The full plugin chain becomes:

```javascript
'use strict'

const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')
const fastifyCsrf = require('@fastify/csrf-protection')

const accountStore = require('./accountStore')

fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})
fastify.register(fastifyCsrf)
```

**Step 2: Add CSRF protection hook to the state-changing route**

Update the POST route to include the CSRF protection hook in its `preHandler` option (lines 48-52):

```javascript
fastify.post(
  '/account/settings',
  {
    preHandler: [fastify.csrfProtection, requireAuthenticatedUser]
  },
  updateSettingsHandler
)
```

The `preHandler` array runs hooks in order: CSRF validation first (which parses the request body to find the token), then authentication check.

**Step 3: Client-side: Include CSRF token in requests**

The client must first fetch the CSRF token via a GET endpoint, then include it in the POST request:

```javascript
// Get token from GET endpoint
const tokenResponse = await fetch('/csrf-token', { credentials: 'include' })
const { token } = await tokenResponse.json()

// Send token in x-csrf-token header for fetch/AJAX
fetch('/account/settings', {
  method: 'POST',
  headers: {
    'x-csrf-token': token,
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify({ displayName, email, notificationsEnabled })
})
```

Or in the request body field `_csrf` for form submissions:

```html
<form method="POST" action="/account/settings">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
  <input type="text" name="displayName">
  <input type="email" name="email">
  <label><input type="checkbox" name="notificationsEnabled"> Enable notifications</label>
  <button type="submit">Update Settings</button>
</form>
```

Add a GET endpoint to mint and return the token:

```javascript
fastify.get('/csrf-token', async (request, reply) => {
  reply.send({ token: reply.generateCsrf() })
})
```

## Explanation

CSRF protection operates on the Synchronizer Token Pattern: the server generates a unique, unpredictable token tied to the user's session, requires the client to include this token in state-changing requests, and validates it before processing. Attackers cannot forge a valid token because it is generated server-side and never leaves the legitimate application's context.

The fix closes three layers:

1. **Middleware registration** (`fastify.register(fastifyCsrf)`) - makes the CSRF validation machinery available to routes.
2. **Route-level hook** (`preHandler: fastify.csrfProtection`) - activates validation for this specific POST endpoint. Without this, the middleware is inert; a route left without the hook remains unprotected.
3. **Client inclusion** - the browser must send the token in either the `x-csrf-token` request header (for AJAX/fetch) or the `_csrf` body field (for forms). A cross-site attacker cannot read this token due to browser same-origin policy, so their forged request will lack it and fail validation.

The token is automatically bound to the session when `@fastify/csrf-protection` runs after `@fastify/session`, so each user's token is distinct and cannot be replayed across sessions. The token is re-issued after login to prevent pre-authentication tokens from being used.

## Behaviour changes

- **Valid requests**: Legitimate POST requests from the application's own forms/JavaScript that correctly include the CSRF token will succeed as before. Requests missing the token or carrying an invalid one will receive a 403 Forbidden response.
- **Invalid requests**: Forged cross-site requests (the attack vector) will be rejected, even if the user is authenticated. Attackers cannot read the token due to same-origin policy, so their forgeries will fail.
- **Client-side requirement**: All forms and AJAX handlers that POST to `/account/settings` must fetch and include the token. Existing hard-coded POST requests without the token will fail until updated.
- **GET endpoints unaffected**: GET requests continue to work without a token (per HTTP semantics, GET should not modify state). If any GET endpoint is changed to perform state-changing operations, it must also be protected or moved to POST/DELETE.
