## Verdict
Exploitable

## Source
HTTP POST request body to `/account/settings` (displayName, email, notificationsEnabled fields) via attacker-crafted cross-site request.

## Fix

**Vulnerable code (lines 3-16, 48-52):**
```javascript
const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')

const accountStore = require('./accountStore')

// @fastify/csrf-protection is never registered in this plugin chain, and no
// route below adds its own CSRF token generation or verification hook.
fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})

// ... handler code ...

fastify.post(
  '/account/settings',
  { preHandler: requireAuthenticatedUser },
  updateSettingsHandler
)
```

**Fixed code:**
```javascript
const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')

const accountStore = require('./accountStore')

fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})
fastify.register(require('@fastify/csrf-protection'))

// ... handler code ...

fastify.post(
  '/account/settings',
  { preHandler: [requireAuthenticatedUser, fastify.csrfProtection] },
  updateSettingsHandler
)
```

## Explanation
The application authenticates users via session cookies but never validates CSRF tokens, allowing attackers to trick authenticated users into performing state-changing operations on their account settings from a malicious website. The fix registers `@fastify/csrf-protection` (8.x) and attaches the `fastify.csrfProtection` hook to the POST route's preHandler chain. Since the CSRF token travels in the request body (not yet parsed at `onRequest`), `preHandler` is used instead of `onRequest`. The hook validates that the request includes a valid server-issued token before passing control to the handler, preventing cross-site request forgery.

## Behaviour changes
- Added `fastify.register(require('@fastify/csrf-protection'))` after session registration (line 16 in fixed code)
- Added `fastify.csrfProtection` to the preHandler array for the POST route (line 24 in fixed code)
- Routes will now reject requests without a valid CSRF token with a 403 Forbidden response
- Clients must obtain a token via `reply.generateCsrf()` in a GET endpoint and include it in subsequent POST requests (in body field `_csrf` or header `x-csrf-token`)
- No changes to the handler's argument contract, return value handling, or error behaviour
