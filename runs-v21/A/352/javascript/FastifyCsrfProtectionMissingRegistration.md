## Verdict

The CSRF vulnerability exists. The `/account/settings` endpoint accepts authenticated requests with state-changing operations but does not validate CSRF tokens. An attacker can craft a cross-site request that modifies an authenticated user's account settings without their consent.

## Source

**File:** accountSettingsRoutes.js  
**Line:** 39 (sink: `accountStore.updateAccountSettings()`)  
**Vulnerable Pattern:** State-changing operation (POST to `/account/settings`) on an authenticated endpoint without CSRF token validation.

The plugin chain registers session support but never registers `@fastify/csrf-protection`, so no CSRF tokens are generated or verified.

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

// Register CSRF protection to validate tokens on state-changing requests.
fastify.register(fastifyCsrfProtection)

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
  { preHandler: [requireAuthenticatedUser, fastify.csrfProtection] },
  updateSettingsHandler
)

module.exports = fastify
```

## Explanation

The fix registers `@fastify/csrf-protection` and adds `fastify.csrfProtection` as a preHandler to the POST route. This ensures:

1. **CSRF token generation:** Fastify generates and associates a CSRF token with each session automatically.
2. **CSRF token validation:** Every POST request to `/account/settings` is validated against the token in the request (typically via a header, body field, or query parameter, depending on the client implementation).
3. **Cross-site request protection:** An attacker cannot forge a valid request without the CSRF token, which is bound to the user's session and never shared in cross-site contexts.

Legitimate clients must retrieve and include the CSRF token in their request to `/account/settings`, preventing unauthorized account modifications initiated from other origins.
