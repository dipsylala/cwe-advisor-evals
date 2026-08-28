## Verdict

exploitable - confidence: high

CWE-209 (Generation of Error Message Containing Sensitive Information) at `RouteBypassesErrorHandler.js:17`. Any exception raised inside the `GET /orders/:id` handler is serialised into the HTTP response body, including the exception message and the full stack trace. The route handles the error itself instead of delegating to the application's error-handling middleware, which already returns a sanitised body.

Sink contract as it stands today: `res.status(500).json(...)` writes the response and ends the request; the returned `Response` object is discarded by Express, so nothing depends on the return value. The handler has no arguments left implicit beyond Express's default JSON serialisation settings. On failure (headers already sent) `res.json` raises `ERR_HTTP_HEADERS_SENT`; nothing downstream depends on that. The only server-side effect worth preserving is `logger.error(error)`.

## Source

- **Source**: the exception thrown inside the `try` block - primarily from `await db.findOrder(req.params.id)` at line 9, where `req.params.id` is attacker-controlled. A malformed or hostile `:id` value reaches the data layer and the resulting driver error (SQL text, connection string fragments, table and column names, driver class names) becomes `error.message`; `error.stack` additionally carries absolute server file paths, module layout, and internal function names.
- **Propagation**: `catch (error)` at line 14 binds that error object; no sanitisation or type narrowing occurs.
- **Sink**: `res.status(500).json({ error: error.message, stack: error.stack })` at line 17 - both properties are serialised straight into the response body returned to the caller.

The path is complete and unconditional: any thrown error in the route reaches the sink with its message and stack intact. An attacker who can provoke a database error (an oversized, wrongly typed, or syntactically hostile `:id`) reads back internal detail on demand.

The error-handling middleware registered at lines 21-24 already implements the correct contract (log server-side, return `{ error: 'Internal Server Error' }`), but the route never reaches it, because the `catch` block responds directly rather than forwarding the error.

## Fix

No library change is required; the fix is code-level only.

**Vulnerable code (lines 7-19):**

```js
app.get('/orders/:id', async (req, res) => {
  try {
    const order = await db.findOrder(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'not found' });
    }
    return res.json(order);
  } catch (error) {
    logger.error(error);
    // VULNERABLE: error.message and error.stack are serialised to the client,
    // exposing driver/SQL detail, server file paths and internal call structure.
    return res.status(500).json({ error: error.message, stack: error.stack });
  }
});
```

**Fixed code:**

```js
app.get('/orders/:id', async (req, res, next) => {
  try {
    const order = await db.findOrder(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'not found' });
    }
    return res.json(order);
  } catch (error) {
    return next(error);
  }
});

app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});
```

The error-handling middleware is unchanged - it is already the fixed, server-controlled error contract. The route now routes into it rather than around it.

## Explanation

The route's `catch` block built the client response out of the caught exception, so the response body was determined by whatever the failing subsystem happened to put in `error.message` and `error.stack` - text the application does not control and cannot review. That is the whole weakness: an error response must come from a fixed, server-authored contract, not from the internals of the failure. The fix forwards the error with `next(error)` to the error-handling middleware already registered on the app, which logs the full error object server-side (so no diagnostic detail is lost to operators) and returns the fixed body `{ error: 'Internal Server Error' }` with status 500. The client now learns only that the request failed, while message, stack, file paths, and any driver or SQL text stay in the log. Adding `next` to the handler signature is what makes the delegation possible; the `try/catch` is retained because Express 4 does not forward rejected promises from an async handler automatically, so without it the rejection would escape the middleware chain entirely. As a deployment-side complement, ensure `NODE_ENV=production` so that no framework default error page can render a stack trace for any path that bypasses this handler.

## Behaviour changes

- **Response body on error changes from `{ error: <driver message>, stack: <stack trace> }` to `{ error: 'Internal Server Error' }`.** This is the fix itself. Any client that parsed `error.message` or `stack` from a 500 response will see them absent; that data was never safe to expose and callers needing detail should be given a correlation id from the log instead. Status code stays 500 and content type stays JSON.
- **`next` added to the handler signature** (`async (req, res, next)`). Required in order to hand the error to the existing error-handling middleware; no other effect.
- **`logger.error(error)` removed from the route's `catch` block.** The middleware the error is now forwarded to performs `logger.error(err)` with the same logger and the same error object, so retaining the call in the route would emit each error twice. Server-side capture of the full error is unchanged in content, only in the place it is emitted from. If the deployment relies on that duplicate line, restore the call in the route - it does not affect the security property either way.
- 404 and success paths are untouched: `res.status(404).json({ error: 'not found' })` and `res.json(order)` behave exactly as before.
- The sink contract from the trace is otherwise preserved - the request is still terminated once, the return value is still discarded by Express, and the headers-already-sent failure mode is unchanged (Express's error handler falls back to its own default in that case).
