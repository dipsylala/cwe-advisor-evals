## Verdict

CWE-352 (Cross-Site Request Forgery) confirmed. The application lacks CSRF token verification on state-changing POST requests, allowing an attacker to forge requests that modify authenticated user account settings.

## Source

File: `accountSettingsRoutes.js`, Line 39

The vulnerability occurs in the flow:
1. Session management and authentication are registered (lines 11-16, 21-27)
2. No CSRF protection plugin is registered (comment confirms this on lines 18-19)
3. POST route at line 48-52 calls `accountStore.updateAccountSettings()` (line 39) without CSRF token verification
4. Authenticated users' sessions are automatically sent with requests (via secure, httpOnly cookies)
5. An attacker-controlled web page can trigger unauthorized account modifications for any authenticated user

## Fix

Register `@fastify/csrf-protection` and add CSRF token verification to the POST route:

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

function requireAuthenticatedUser(request, reply, done) {
  if (!request.session || !request.session.userId) {
    reply.code(401).send({ error: 'authentication required' })
    return
  }
  done()
}

async function updateSettingsHandler(request, reply) {
  const userId = request.session.userId
  const { displayName, email, notificationsEnabled } = request.body || {}

  if (!displayName || !email) {
    reply.code(400).send({ error: 'displayName and email are required' })
    return
  }

  const updated = await accountStore.updateAccountSettings(userId, {
    displayName,
    email,
    notificationsEnabled: Boolean(notificationsEnabled)
  })

  reply.code(200).send({ status: 'updated', account: updated })
}

fastify.post(
  '/account/settings',
  { preHandler: requireAuthenticatedUser },
  updateSettingsHandler
)

module.exports = fastify
```

## Explanation

The fix addresses CWE-352 by implementing CSRF token validation:

1. **Plugin Registration**: `@fastify/csrf-protection` is registered in the plugin chain. This plugin automatically:
   - Generates a CSRF token tied to each session
   - Validates tokens on state-changing requests (POST, PUT, DELETE, PATCH)
   - Rejects requests without valid tokens, even if the user is authenticated

2. **Token Verification**: The plugin's `preHandler` hook intercepts POST requests before they reach the route handler. It verifies the CSRF token is present and matches the session's token. Requests without a valid token are rejected with a 403 Forbidden response.

3. **Session Binding**: Because CSRF tokens are bound to the session (initialized on lines 12-16 before CSRF registration), tokens are unique per user and cannot be reused across sessions.

The fix preserves the existing session security posture (secure, httpOnly, sameSite cookies) while adding the second layer of protection—token verification—that prevents an attacker from crafting requests on behalf of an authenticated user, even if they know the user is authenticated to the application.
