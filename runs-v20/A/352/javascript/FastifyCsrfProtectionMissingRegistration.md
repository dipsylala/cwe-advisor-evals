## Verdict

Confirmed. `accountSettingsRoutes.js` registers `@fastify/cookie` and `@fastify/session`, which is exactly what makes the app CSRF-exploitable: the session cookie is sent automatically by the browser on a cross-site request, but the plugin chain never registers `@fastify/csrf-protection` and no hook on the `POST /account/settings` route checks a CSRF token. A remote page can submit a cross-origin form/fetch to this endpoint and, as long as the victim has an authenticated session cookie, `requireAuthenticatedUser` passes and `accountStore.updateAccountSettings` runs with attacker-chosen `displayName`/`email`/`notificationsEnabled`.

## Source

`request.body` (`displayName`, `email`, `notificationsEnabled`) submitted via `POST /account/settings`, authenticated only by the ambient session cookie set by `@fastify/session`.

## Fix

Register `@fastify/csrf-protection` (tied to the already-registered `@fastify/session` plugin) and add its verification hook to the state-changing route's `preHandler` chain, alongside a route to issue the token to legitimate same-origin clients.

### File: accountSettingsRoutes.js
```javascript
'use strict'

const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')
const fastifyCsrf = require('@fastify/csrf-protection')

const accountStore = require('./accountStore')

// Cookie parsing and session support are registered, so every request from
// an authenticated browser carries the session cookie automatically.
fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})

// @fastify/csrf-protection is registered and tied to the session plugin so the
// CSRF secret rides in the existing session rather than a separate cookie.
// Registering it decorates the instance with `csrfProtection` (a preHandler
// that verifies the token) and decorates `reply` with `generateCsrf()`.
fastify.register(fastifyCsrf, { sessionPlugin: '@fastify/session' })

function requireAuthenticatedUser(request, reply, done) {
  if (!request.session || !request.session.userId) {
    reply.code(401).send({ error: 'authentication required' })
    return
  }
  done()
}

async function getCsrfTokenHandler(request, reply) {
  const token = await reply.generateCsrf()
  reply.code(200).send({ csrfToken: token })
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

fastify.get(
  '/account/csrf-token',
  { preHandler: requireAuthenticatedUser },
  getCsrfTokenHandler
)

fastify.post(
  '/account/settings',
  { preHandler: [requireAuthenticatedUser, fastify.csrfProtection] },
  updateSettingsHandler
)

module.exports = fastify
```

## Explanation

`@fastify/csrf-protection` is registered with `sessionPlugin: '@fastify/session'` so it stores and reads the CSRF secret from the session that's already set up, instead of introducing a second, unrelated cookie. Registration decorates the Fastify instance with `csrfProtection`, a preHandler that reads the token from the request (header, body, or query, per the plugin's default token extractor), compares it against the secret held server-side in the session, and rejects the request with a 403 when it's missing or wrong.

`POST /account/settings` now runs `csrfProtection` after `requireAuthenticatedUser` in its `preHandler` array, so a cross-site request that rides on the victim's ambient session cookie but carries no valid CSRF token is rejected before `accountStore.updateAccountSettings` is ever called - closing the sink at line 39 of the original file.

A same-origin page needs a way to obtain a token before it can submit the form, so a companion `GET /account/csrf-token` route is added, gated behind the same authentication check, calling `reply.generateCsrf()` (decorated onto `reply` by the plugin) and returning the token for the client to echo back on the subsequent `POST`. This keeps `sameSite: 'lax'` on the session cookie as defense-in-depth while making CSRF-token verification the primary control on the mutating route, matching how `@fastify/csrf-protection` is documented to pair with `@fastify/session`.
