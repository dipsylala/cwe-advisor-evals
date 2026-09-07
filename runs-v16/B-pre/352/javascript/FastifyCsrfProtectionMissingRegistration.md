## Verdict

This is a confirmed CWE-352 (Cross-Site Request Forgery) vulnerability. The POST route at `/account/settings` modifies account settings for an authenticated user without validating a server-issued CSRF token, allowing an attacker to force the user to change their email, display name, and notification settings via a crafted cross-site request.

## Source

File: `accountSettingsRoutes.js`, lines 48–52 (POST route registration) and line 39 (state-changing operation sink).

The route accepts authenticated users and processes account modifications without CSRF protection:

```javascript
fastify.post(
  '/account/settings',
  { preHandler: requireAuthenticatedUser },
  updateSettingsHandler
)
```

The `preHandler` array includes only authentication verification. The `@fastify/csrf-protection` plugin is not registered, and the route has no CSRF token validation hook.

## Fix

**Step 1: Add the plugin import**

After line 5, add:

```javascript
const fastifyCsrfProtection = require('@fastify/csrf-protection')
```

**Step 2: Register the CSRF protection plugin**

After line 16 (after `fastify.register(fastifySession, ...)`), add:

```javascript
fastify.register(fastifyCsrfProtection)
```

**Step 3: Attach the CSRF protection hook to the POST route**

Replace lines 48–52 with:

```javascript
fastify.post(
  '/account/settings',
  { preHandler: [requireAuthenticatedUser, fastify.csrfProtection] },
  updateSettingsHandler
)
```

## Explanation

The fix adds the `@fastify/csrf-protection` middleware and attaches the CSRF validation hook to the POST route. The hook is placed in the `preHandler` array (rather than `onRequest`) because the client sends the token in the request body or custom header, which Fastify parses after `onRequest` but before `preHandler`.

When registered, `@fastify/csrf-protection` binds a CSRF token to each authenticated session. The client must include this token when submitting the form (as a hidden `_csrf` field in POST forms, or as an `x-csrf-token` header in XHR/fetch requests). On the server side, the `fastify.csrfProtection` hook verifies that the request carries a valid token matching the session before the handler runs. Invalid or missing tokens are rejected with a 403 response.

The fix preserves all existing route behavior: authentication checks remain first in the `preHandler` chain, the request body is processed identically, and successful updates still return 200 with the updated account object.

**Assumption**: The fix assumes the client will supply the CSRF token via either a `_csrf` body field (for HTML forms) or an `x-csrf-token` header (for XHR/fetch). The client must first obtain the token via a GET endpoint that calls `reply.generateCsrf()`, or the token is available in the session.

## Behaviour changes

- POST requests to `/account/settings` that do not include a valid CSRF token now receive a 403 Forbidden response instead of processing the account update.
- Successful requests require an additional `_csrf` field or `x-csrf-token` header to be sent by the client.
- The server now binds the CSRF token to the user's session, preventing token reuse across sessions or users.
