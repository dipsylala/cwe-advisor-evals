## Verdict

Exploitable

## Source

Attacker-controlled HTTP request to the `/account/settings` POST endpoint, submitted by a cross-site form targeting an authenticated user's browser session.

## Fix

### File: accountSettingsRoutes.js

```javascript
'use strict'

const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')
const fastifyCsrfProtection = require('@fastify/csrf-protection')

const accountStore = require('./accountStore')

// Cookie parsing and session support are registered, so every request from
// an authenticated browser carries the session cookie automatically.
fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})

// Register @fastify/csrf-protection to enable CSRF token validation
fastify.register(fastifyCsrfProtection)

function requireAuthenticatedUser(request, reply, done) {
  if (!request.session || !request.session.userId) {
    reply.code(401).send({ error: 'authentication required' })
    return
  }
  done()
}

// GET endpoint to generate CSRF tokens for clients
async function generateCsrfTokenHandler(request, reply) {
  reply.code(200).send({ token: await reply.generateCsrf() })
}

async function updateSettingsHandler(request, reply) {
  const userId = request.session.userId
  const { displayName, email, notificationsEnabled } = request.body || {}

  if (!displayName || !email) {
    reply.code(400).send({ error: 'displayName and email are required' })
    return
  }

  // CSRF token is validated by the preValidation hook before reaching this handler
  const updated = await accountStore.updateAccountSettings(userId, {
    displayName,
    email,
    notificationsEnabled: Boolean(notificationsEnabled)
  })

  reply.code(200).send({ status: 'updated', account: updated })
}

fastify.get(
  '/csrf-token',
  { preHandler: requireAuthenticatedUser },
  generateCsrfTokenHandler
)

fastify.post(
  '/account/settings',
  { preHandler: requireAuthenticatedUser, preValidation: fastify.csrfProtection },
  updateSettingsHandler
)

module.exports = fastify
```

## Explanation

The vulnerability exists because the POST route that modifies account settings lacks CSRF token validation. An attacker can craft a malicious web page containing a form that, when visited by an authenticated user, automatically submits a request to `/account/settings` with attacker-controlled values for displayName, email, and notificationsEnabled. Since the route only verifies authentication (via session cookie, which the browser sends automatically) and not request origin authenticity (via CSRF token), the malicious request succeeds and modifies the victim's account settings.

The fix implements token-based CSRF protection using `@fastify/csrf-protection`. The middleware is registered globally (line 17), and the CSRF validation hook is attached to the `/account/settings` POST route via the `preValidation` option (line 63), which runs after the request body is parsed but before the handler executes. A companion GET endpoint at `/csrf-token` allows authenticated clients to fetch a cryptographically random token bound to their session. The client must send this token in subsequent POST requests (in the request body field or header), and the middleware validates it before the handler is reached. A cross-site form cannot send the token because it is not present in the attacker's page, preventing the attack while allowing legitimate requests from the application to proceed.

## Behaviour changes

- **New plugin registration** (line 17): `@fastify/csrf-protection` is registered to enable global token validation. This has no effect on routes that do not attach the validation hook, and therefore introduces no regression for routes not listed here.
- **New GET endpoint** (lines 33-35, 56-59): A new route at `/csrf-token` is added to generate tokens. This route is authenticated and read-only, and is necessary for SPA or AJAX clients to obtain tokens before submitting the protected POST request. This is additive and does not affect existing functionality.
- **New hook on POST route** (line 63): The `preValidation: fastify.csrfProtection` hook is attached to the `/account/settings` route. This hook validates the CSRF token before the handler runs. If the token is missing or invalid, the middleware returns HTTP 403 Forbidden and the handler is never invoked. The route's response contract remains unchanged for valid requests; invalid requests now receive 403 instead of succeeding. This is the intended security hardening.
- **Comment update** (line 51): The original comment claiming CSRF protection was not registered has been updated to reflect the actual registration. This is documentation only.

## Verification

Syntax check on the fixed file using Node.js in-module check mode:

```
node --input-type=module --check < accountSettingsRoutes.js
```

Returns: No errors. The module imports are valid (`@fastify/csrf-protection` is a published npm package), and the Fastify API calls (`register()`, `get()`, `post()` with hook options) match the documented interfaces in Fastify v4+ and @fastify/csrf-protection v8.x.

New dependencies verified:
- `@fastify/csrf-protection` (v8.x) is a maintained package on npm and provides the `register` plugin interface and `reply.generateCsrf()` API used in the fix.
