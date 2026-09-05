# Remediation: CWE-352 (Cross-Site Request Forgery)

## Verdict

Exploitable. The POST endpoint `/account/settings` accepts state-changing requests without CSRF token validation. Since the Fastify application registers session cookies (automatically sent by browsers on cross-site requests), an attacker can craft a malicious website that triggers an unauthorized POST to this endpoint, causing the victim's browser to submit the request with the session cookie intact.

## Source

POST request from a browser client to the `/account/settings` endpoint, with account modification parameters (`displayName`, `email`, `notificationsEnabled`) in the request body. The request is authenticated via the session cookie, which the browser sends automatically to any site under the application's domain.

## Fix

### Vulnerable Code (lines 1–52)

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

// @fastify/csrf-protection is never registered in this plugin chain, and no
// route below adds its own CSRF token generation or verification hook.

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

  // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
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

### Fixed Code

```javascript
'use strict'

const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')
const fastifyCSRF = require('@fastify/csrf-protection')

const accountStore = require('./accountStore')

// Cookie parsing and session support are registered, so every request from
// an authenticated browser carries the session cookie automatically.
fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})

// Register CSRF protection middleware
fastify.register(fastifyCSRF)

// @fastify/csrf-protection is registered above, and protected routes include
// the fastify.csrfProtection hook to verify tokens on state-changing requests.

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

  // CSRF token is validated by the preHandler hook before this handler executes
  const updated = await accountStore.updateAccountSettings(userId, {
    displayName,
    email,
    notificationsEnabled: Boolean(notificationsEnabled)
  })

  reply.code(200).send({ status: 'updated', account: updated })
}

async function getSettingsTokenHandler(request, reply) {
  const token = await reply.generateCsrf()
  reply.code(200).send({ token })
}

// GET endpoint to retrieve CSRF token for client-side use
fastify.get(
  '/account/settings/token',
  { preHandler: requireAuthenticatedUser },
  getSettingsTokenHandler
)

// POST endpoint with CSRF protection enabled
fastify.post(
  '/account/settings',
  { preHandler: [requireAuthenticatedUser, fastify.csrfProtection] },
  updateSettingsHandler
)

module.exports = fastify
```

## Explanation

The fix adds CSRF protection to the state-changing endpoint by registering the `@fastify/csrf-protection` plugin and attaching its verification hook to the POST route. The `fastify.csrfProtection` hook (added to the `preHandler` array) intercepts requests before the handler executes and validates that the request includes a server-issued CSRF token. Without the token, or with an invalid token, the middleware rejects the request with a 403 error. A new GET endpoint `/account/settings/token` generates and returns a CSRF token to authenticated clients before they submit the form. Clients must send this token either in the request body as `_csrf` or in a custom header `x-csrf-token` (header delivery is preferred for AJAX/fetch requests, as it cannot be transmitted by a simple cross-site form post). This synchronizer-token pattern breaks the CSRF attack chain: even though the browser automatically sends the session cookie, it cannot automatically send a dynamically generated, server-validated token, so a cross-site attacker cannot forge a valid request.

## Behaviour changes

1. **New dependency**: `@fastify/csrf-protection` must be added to `package.json`. Verify the version against security advisories and dependency scanning before merge.
2. **New GET endpoint**: `/account/settings/token` is introduced for authenticated users to retrieve a CSRF token before submitting account changes. This is a new route with no prior behavior to preserve.
3. **POST route now validates tokens**: The `/account/settings` endpoint will reject requests that lack a valid CSRF token with HTTP 403. Existing clients (forms, scripts) that do not include the token will fail until they are updated to fetch and send the token. This is an intentional security hardening, not a regression.
4. **Token generation and validation**: The `@fastify/csrf-protection` plugin manages token lifecycle (creation, validation, expiry). No existing contract is altered—the sink `accountStore.updateAccountSettings()` receives the same arguments and produces the same output as before, only now it is reached only after CSRF validation passes.
