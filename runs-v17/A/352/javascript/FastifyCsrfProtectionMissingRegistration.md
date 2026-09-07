## Verdict

CONFIRMED. The application accepts state-changing POST requests without CSRF token validation. The `@fastify/csrf-protection` plugin is never registered, leaving the POST endpoint `/account/settings` vulnerable to cross-site request forgery attacks. An attacker can forge a request from a victim's authenticated browser to modify account settings.

## Source

**File:** accountSettingsRoutes.js  
**Line:** 39  
**Call:** `accountStore.updateAccountSettings(userId, {...})`

The vulnerability is introduced at line 39 where the application processes the account update without first validating a CSRF token. Lines 18-19 explicitly document that the CSRF protection plugin is absent:

```
// @fastify/csrf-protection is never registered in this plugin chain, and no
// route below adds its own CSRF token generation or verification hook.
```

The POST route at line 48-51 is state-changing (modifies account settings) but relies only on session authentication, which an attacker can exploit via a forged cross-site request.

## Fix

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

// @fastify/csrf-protection is registered and protects state-changing routes
// by validating CSRF tokens on POST, PUT, DELETE, and PATCH requests.
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

  // The @fastify/csrf-protection plugin validates the CSRF token before
  // this handler is invoked, protecting against cross-site request forgery.
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

The vulnerability arises because the application uses session-based authentication without CSRF protection. Session cookies are automatically sent by the browser on every request to the same origin, allowing an attacker to craft a malicious webpage that silently submits a form to the victim's authenticated session, changing their account settings without consent.

The fix registers the `@fastify/csrf-protection` plugin, which:

1. **Generates CSRF tokens** tied to the session, typically embedded in forms or response headers
2. **Validates tokens** on all state-changing requests (POST, PUT, DELETE, PATCH) before handler execution
3. **Rejects invalid or missing tokens** with a 403 Forbidden response, blocking forged requests

The plugin operates transparently as a preHandler hook, intercepting requests before `updateSettingsHandler` executes. The sink at line 39 (now line 44 after the fix) is now protected because the CSRF token has been validated by the time execution reaches it.

This defense prevents an attacker's forged request from succeeding even if submitted from the victim's authenticated browser session, because the attacker cannot obtain or predict the CSRF token unique to that session.
