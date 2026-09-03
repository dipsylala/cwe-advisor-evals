## Verdict

**Confirmed.** The application accepts state-changing POST requests without verifying a CSRF token. An authenticated user can be tricked into submitting requests that modify their account settings via a cross-origin request.

## Source

`accountSettingsRoutes.js`, line 39: The `updateSettingsHandler` processes a POST request containing user-controlled data (`displayName`, `email`, `notificationsEnabled`) and persists it directly to the account store without validating a CSRF token. The application has registered `@fastify/cookie` and `@fastify/session` (lines 11-16), which automatically transmit the session cookie with every request from a browser, but has not registered `@fastify/csrf-protection` (noted in lines 18-19) and performs no per-route CSRF token verification.

## Fix

1. **Register the CSRF protection plugin** at the top level before defining routes:

   ```javascript
   const fastifyCsrf = require('@fastify/csrf-protection')
   fastify.register(fastifyCsrf)
   ```

2. **Verify the CSRF token on the POST route** by adding a `preHandler` hook that calls the plugin's built-in CSRF verification:

   ```javascript
   fastify.post(
     '/account/settings',
     { preHandler: [requireAuthenticatedUser, fastify.csrfProtection] },
     updateSettingsHandler
   )
   ```

3. **Ensure the client includes the CSRF token** in form submissions. The token can be injected into the page when rendering the form, and the client must send it either as a hidden form field, request header, or query parameter depending on the transport mechanism.

## Explanation

CSRF attacks exploit the browser's automatic inclusion of cookies in cross-origin requests. By requiring a CSRF token that only the legitimate application can generate and that an attacker cannot read from a cross-origin page (due to browser same-origin policy), the server can distinguish legitimate requests from forged ones.

The `@fastify/csrf-protection` plugin generates a token tied to the user's session and validates it on each protected request. When the plugin is registered, it exposes a `fastify.csrfProtection` hook that can be added to route handlers as a `preHandler`. The plugin automatically extracts the token from the request (supporting multiple delivery methods) and rejects requests with invalid or missing tokens.

Authentication alone is insufficient: a session cookie is automatically sent by the browser regardless of where the request originated, so an attacker can exploit authenticated users by tricking them into making a request to the target application from a malicious site. Adding CSRF token validation closes this attack surface.
