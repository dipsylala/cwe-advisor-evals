## Verdict

- **CWE-209**: Generation of Error Message Containing Sensitive Information
- **Location**: `RouteBypassesErrorHandler.js:17`
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: the `error` object caught from `db.findOrder(req.params.id)` (`RouteBypassesErrorHandler.js:9`) - any failure there (a database driver exception, a connection error, a malformed-id error) lands in the `catch` block carrying engine-specific detail (message text, and for many Node DB drivers, query/connection info) plus a full stack trace.
- **Sink**: `res.status(500).json({ error: error.message, stack: error.stack })` at line 17, inside the route's own `catch` block.
- **Path**: the route registers a correctly-written centralized error handler (`app.use((err, req, res, next) => {...})`, lines 21-24) that already returns a generic `Internal Server Error` message. But the route never reaches it - the `catch` block answers the client directly instead of calling `next(error)`, so the centralized handler's sanitization is bypassed entirely for this route. The error's `message` and full `stack` are serialized straight into the JSON response body sent to the caller.

## Fix

Vulnerable code:

```javascript
app.get('/orders/:id', async (req, res) => {
  try {
    const order = await db.findOrder(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'not found' });
    }
    return res.json(order);
  } catch (error) {
    logger.error(error);
    // SAST FINDING: CWE-209 (Information Exposure Through an Error Message) reported here. Sink is the next statement.
    return res.status(500).json({ error: error.message, stack: error.stack });
  }
});
```

Fixed code:

```javascript
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
```

## Explanation

The route's `catch` block answered the client itself, so the application's own centralized error handler - which already implements the correct generic-message pattern - never ran for this endpoint. The fix removes the direct response and forwards the caught error to Express via `next(error)`, letting the existing downstream middleware (`app.use((err, req, res, next) => {...})`) log the full error server-side and return the sanitized `{ error: 'Internal Server Error' }` body with status 500. No new middleware or generic-message logic was written, because a correct implementation already exists in the file; the only change needed was routing this handler's failures into it instead of around it.

## Behaviour changes

- The client-visible error body changes from `{ error: error.message, stack: error.stack }` to `{ error: 'Internal Server Error' }`. This is the intended effect of the fix, not a side effect.
- The route's own `logger.error(error)` call was removed. Forwarding via `next(error)` routes the error into the centralized handler, which itself calls `logger.error(err)` before responding - keeping the route's local call would have logged every failure twice. Server-side logging of the full error (message and stack) is preserved; it now happens once, in the centralized handler, instead of twice.
- The route handler signature gains an unused `next` parameter, required by Express to forward the error; it is not otherwise used.
- The HTTP status code for this failure path remains 500 in both versions - unchanged.
- The `404` branch for a missing order is untouched and still returns `{ error: 'not found' }` directly, since that message is a fact about the request (no such order) and was not part of the reported finding.
