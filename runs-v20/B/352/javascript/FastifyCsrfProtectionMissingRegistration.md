## Verdict

exploitable (confidence: high)

CWE-352 (Cross-Site Request Forgery). `accountSettingsRoutes.js:39` is the reported sink, inside `updateSettingsHandler`. `@fastify/cookie` and `@fastify/session` are registered so every authenticated browser request carries the session cookie automatically, but `@fastify/csrf-protection` is never registered and no route attaches a CSRF hook. The route's only gate is `requireAuthenticatedUser` (`preHandler`), which checks for a valid session but performs no origin/token verification. `SameSite: 'lax'` on the session cookie is a partial mitigant for classic auto-submitting cross-site `<form>` POSTs in modern browsers, but it is a browser-enforced default, not a substitute for a server-side token, and does not protect against non-browser or misconfigured clients. The path is live: an attacker page that causes the victim's browser to send a cross-site POST/fetch (`credentials: 'include'`) to `/account/settings` while the victim has an active session reaches `accountStore.updateAccountSettings` and overwrites the victim's `displayName`, `email`, and `notificationsEnabled`, with no verification that the request originated from the application's own UI.

## Source

- **Source**: the JSON request body (`displayName`, `email`, `notificationsEnabled`) of `POST /account/settings`, submitted by a browser that holds the victim's session cookie.
- **Intermediate**: `requireAuthenticatedUser` (preHandler) confirms `request.session.userId` exists but does not check request origin or authenticity.
- **Sink**: `accountStore.updateAccountSettings(userId, { displayName, email, notificationsEnabled })` at line 39 - a state-changing write keyed only by the session-derived `userId`, reachable by any site that can make the victim's browser issue the POST.

## Fix

### File: accountSettingsRoutes.js

```javascript
'use strict'

const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')
const fastifyCsrfProtection = require('@fastify/csrf-protection')

const accountStore = require('./accountStore')

function requireAuthenticatedUser(request, reply, done) {
  if (!request.session || !request.session.userId) {
    reply.code(401).send({ error: 'authentication required' })
    return
  }
  done()
}

async function issueCsrfTokenHandler(request, reply) {
  const csrfToken = await reply.generateCsrf()
  reply.code(200).send({ csrfToken })
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

fastify.register(async function accountSettingsPlugin(fastify) {
  // Cookie parsing and session support are registered, so every request from
  // an authenticated browser carries the session cookie automatically.
  await fastify.register(fastifyCookie)
  await fastify.register(fastifySession, {
    secret: process.env.SESSION_SECRET,
    cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
    saveUninitialized: false
  })

  // CSRF secrets are stored on the session established above, so a token
  // minted for one session cannot be replayed against another. `await` on
  // this registration matters: fastify.csrfProtection is not decorated onto
  // the instance until the plugin finishes loading, and the route option
  // objects below capture it by value at route-definition time.
  await fastify.register(fastifyCsrfProtection, { sessionPlugin: '@fastify/session' })

  fastify.get(
    '/account/settings/csrf-token',
    { preHandler: requireAuthenticatedUser },
    issueCsrfTokenHandler
  )

  fastify.post(
    '/account/settings',
    {
      preHandler: requireAuthenticatedUser,
      onRequest: fastify.csrfProtection
    },
    updateSettingsHandler
  )
})

module.exports = fastify
```

**Dependency**: add `@fastify/csrf-protection` to the project's `package.json` (not present in this case's file set, so no manifest is included above). The knowledge base names the `8.x` line as the release compatible with Fastify `5.x` - it is not a CVE-driven security floor, so confirm the exact resolved version against SCA/dependency-check tooling before merging rather than treating `8.x` as a minimum-safe pin.

## Explanation

The fix registers `@fastify/csrf-protection` with `sessionPlugin: '@fastify/session'`, so the CSRF secret is stored on the same server-side session already used for authentication, and attaches `fastify.csrfProtection` as an `onRequest` hook on the `/account/settings` route so every request must carry a valid, session-bound token before `updateSettingsHandler` (and therefore the sink) runs; a new `GET /account/settings/csrf-token` route lets an authenticated client obtain that token via `reply.generateCsrf()` for a legitimate AJAX/fetch flow (client sends it back as `x-csrf-token`, the header default `@fastify/csrf-protection` checks). Registration of `@fastify/cookie`, `@fastify/session`, and `@fastify/csrf-protection` moved from three sequential top-level `fastify.register()` calls into one `await`-sequenced nested plugin: `fastify.csrfProtection` does not exist on the instance until `@fastify/csrf-protection` finishes loading, and the route-options object (`{ onRequest: fastify.csrfProtection }`) reads that property once, synchronously, at the line where the route is defined - without the `await`, the property is read while still `undefined` and the route ends up with no CSRF hook at all despite the registration call being present (confirmed by reproducing exactly that against the real package: the flat, unawaited version silently let an unauthenticated, tokenless POST through with a 200). Together this closes the CWE-352 gap: a cross-site request that only carries the ambient session cookie no longer has a way to supply the required token and is rejected before `accountStore.updateAccountSettings` runs.

## Behaviour changes

- New route added: `GET /account/settings/csrf-token` (gated by the existing `requireAuthenticatedUser`), needed so a legitimate client has a way to obtain a token before it can successfully POST. Any existing client of `POST /account/settings` must be updated to call this route first and send the returned value back as the `x-csrf-token` header - without that change, a legitimate authenticated client's POST now also fails (by design: it is indistinguishable from a forged one without a token).
- Failure precedence on a request that is both unauthenticated and tokenless: previously 401 (`requireAuthenticatedUser` was the only gate); now 403 `FST_CSRF_MISSING_SECRET` (`fastify.csrfProtection` runs at `onRequest`, before the `preHandler` auth check). Both paths reject the request; only the status code and error body for that one combination change.
- `@fastify/cookie`, `@fastify/session`, and `@fastify/csrf-protection` registration moved from the top-level `fastify` instance into a nested `fastify.register(async function accountSettingsPlugin(fastify) {...})`, required so the `await`s can run before the routes are defined (see Explanation). `module.exports = fastify` still exports the same top-level instance, and both routes remain reachable at the same paths - no external caller of this module observes a difference from this restructuring alone.
- All other behaviour is unchanged: `updateSettingsHandler`'s validation, its call shape to `accountStore.updateAccountSettings`, and its response body are identical to the original.
- Confidence: high, given the runtime verification below. Assumption: the token-transport choice (custom `x-csrf-token` header, `sessionPlugin: '@fastify/session'` rather than the double-submit cookie mode) was chosen because a header keeps the check at `onRequest` without waiting on body parsing and because the app already has `@fastify/session`; no other consumer of this route was visible in the case file set to confirm against.
- Verification: `node --check` on the fixed file (passed - no syntax errors). Additionally, ran the fixed route file (plus a stub `accountStore.updateAccountSettings`) under the real, installed `@fastify/csrf-protection@8.0.1` with `fastify@5.x`, `@fastify/cookie`, and `@fastify/session`, via `fastify.inject`: an authenticated POST with no `x-csrf-token` returned 403 (`FST_CSRF_MISSING_SECRET`); fetching `/account/settings/csrf-token` and replaying that token in `x-csrf-token` on the POST returned 200 with the expected updated-account body; replaying the authenticated session cookie without the token (the forged-request case) returned 403 (`FST_CSRF_INVALID_TOKEN`). This also confirms `reply.generateCsrf()` returns a Promise in this package version and must be `await`ed, and confirms the `await fastify.register(...)` ordering is required - an unawaited version of the same code let the tokenless POST through with 200 in the same harness.
