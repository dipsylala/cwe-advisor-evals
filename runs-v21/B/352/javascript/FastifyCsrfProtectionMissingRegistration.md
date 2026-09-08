## Verdict

**CONFIRMED** - CWE-352 (Cross-Site Request Forgery). The POST endpoint `/account/settings` at line 39 modifies account settings without CSRF token validation. The `@fastify/csrf-protection` plugin is never registered, and the vulnerable route has no CSRF protection hook. An attacker can forge a request exploiting an authenticated user's session cookie.

## Source

**File**: `accountSettingsRoutes.js`

**Line**: 39 (sink: `accountStore.updateAccountSettings()`)

**Data flow**: 
- User makes authenticated POST request to `/account/settings` with session cookie
- Fastify session middleware (line 12) sets `request.session` from the cookie
- `requireAuthenticatedUser` preHandler (line 21) verifies `request.session.userId` exists
- Request body is parsed and passed to `updateSettingsHandler` (line 29)
- Line 39 calls the sink without any CSRF token verification

**Root cause**: The plugin `@fastify/csrf-protection` is not registered (lines 18-19 document this), and no route has the `fastify.csrfProtection` hook to enforce token validation before the handler runs.

## Fix

### File: accountSettingsRoutes.js

```javascript
'use strict'

const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')

const accountStore = require('./accountStore')

// Cookie parsing and session support are registered, so every request from
// an authenticated browser carries the session cookie automatically.
fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})

// Register @fastify/csrf-protection to enable CSRF token generation and validation.
fastify.register(require('@fastify/csrf-protection'))

function requireAuthenticatedUser(request, reply, done) {
  if (!request.session || !request.session.userId) {
    reply.code(401).send({ error: 'authentication required' })
    return
  }
  done()
}

// Endpoint to generate CSRF token for client (GET requests)
fastify.get(
  '/csrf-token',
  { preHandler: requireAuthenticatedUser },
  async (request, reply) => {
    return { csrfToken: await reply.generateCsrf() }
  }
)

async function updateSettingsHandler(request, reply) {
  const userId = request.session.userId
  const { displayName, email, notificationsEnabled } = request.body || {}

  if (!displayName || !email) {
    reply.code(400).send({ error: 'displayName and email are required' })
    return
  }

  // CSRF token is now validated by the onRequest hook before this handler runs.
  const updated = await accountStore.updateAccountSettings(userId, {
    displayName,
    email,
    notificationsEnabled: Boolean(notificationsEnabled)
  })

  reply.code(200).send({ status: 'updated', account: updated })
}

fastify.post(
  '/account/settings',
  { onRequest: fastify.csrfProtection, preHandler: requireAuthenticatedUser },
  updateSettingsHandler
)

module.exports = fastify
```

## Explanation

The fix implements CSRF protection in three parts:

1. **Plugin Registration** (line 19): `@fastify/csrf-protection` is registered. This initializes the plugin's internal state for token generation and validation.

2. **Token Generation Endpoint** (lines 29-35): A GET endpoint `/csrf-token` mints fresh tokens via `reply.generateCsrf()` bound to the user's session. The client calls this before submitting the form/fetch request to obtain the token.

3. **Token Validation Hook** (line 52): The POST route now has `onRequest: fastify.csrfProtection` in its options. This hook runs before authentication and body parsing, extracting the token from the `x-csrf-token` header (for API/fetch calls) or `_csrf` body field (for forms). It validates the token against the session-bound state before the handler runs. If validation fails, the middleware returns 403 Forbidden.

The `preHandler: requireAuthenticatedUser` runs after the CSRF check, ensuring both the token is valid (request is from the application) and the user is authenticated (via session).

The session cookie's `sameSite: 'lax'` (line 14) provides defence-in-depth by preventing cross-site form submissions from including the session cookie in non-safe contexts (though the CSRF token is the primary defence).

## Behaviour changes

- **New GET endpoint**: `/csrf-token` now available. Authenticated clients must call this first to retrieve a CSRF token before making POST requests.
- **POST `/account/settings` now requires CSRF token**: Requests without a valid token receive 403 Forbidden. Clients must include the token in the `x-csrf-token` header (XHR/fetch) or as `_csrf` in the request body (forms).
- **Token binding**: Each token is cryptographically bound to the user's session and is invalidated if the session is regenerated (e.g., at login).
- **Existing legitimate requests**: Any client not providing a valid CSRF token will now fail. Client code must be updated to fetch the token and include it in state-changing requests.
