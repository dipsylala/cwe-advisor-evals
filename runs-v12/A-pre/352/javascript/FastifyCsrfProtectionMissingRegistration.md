## Verdict
CONFIRMED: Cross-Site Request Forgery vulnerability on the `POST /account/settings` route due to missing CSRF token protection.

## Source
The route accepts authenticated POST requests that modify account settings without validating a CSRF token. The `@fastify/csrf-protection` plugin is not registered, and the route has no CSRF verification hook. An attacker can forge a request from another site that an authenticated user's browser will execute automatically with their session cookie, changing the user's settings without their knowledge.

## Fix
Register `@fastify/csrf-protection` in the plugin chain and add the CSRF hook to the route:

```javascript
const fastifyCsrfProtection = require('@fastify/csrf-protection')

fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})
fastify.register(fastifyCsrfProtection)

fastify.post(
  '/account/settings',
  { preHandler: [fastify.csrfProtection, requireAuthenticatedUser] },
  updateSettingsHandler
)
```

The CSRF token must also be included in the client request either as a form field named `_csrf` or as an `x-csrf-token` header.

## Explanation
By registering `@fastify/csrf-protection` and adding `fastify.csrfProtection` to the route's preHandler hooks, the server validates that state-changing POST requests include a valid CSRF token. This prevents forged requests from other origins, since the attacker cannot access the token—it is stored in the session and verified server-side. The sameSite=lax cookie setting alone is insufficient because it permits same-site POST requests and some cross-site contexts; CSRF token verification is the standard defence.
