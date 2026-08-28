# CWE-209 - RouteBypassesErrorHandler.js

## Verdict

Confirmed. Line 17 serializes `error.message` and `error.stack` straight into the HTTP 500 response body, so any unhandled failure inside `db.findOrder` is disclosed to the caller.

The stack trace exposes absolute source paths, module and function names, and the internal call chain; driver-generated messages routinely carry the failing SQL text, table and column names, connection targets, and credential or hostname fragments. That output gives an attacker a map of the application's internals and, because error text varies with input, a reliable oracle for probing `:id`.

The file already registers a correct centralized error handler at lines 21-24 that returns a generic `Internal Server Error`. The route's own `catch` block never reaches it - it terminates the response itself, so the safe handler is dead code for this route. The weakness is the bypass, not a missing control.

## Source

`evals/cases/209/javascript/RouteBypassesErrorHandler/RouteBypassesErrorHandler.js`

```js
const express = require('express');
const db = require('./db');
const logger = require('./logger');

const app = express();

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

app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
```

## Fix

Route the failure into the existing error middleware instead of answering from the handler, and give the client a correlation id in place of the diagnostics.

```js
const express = require('express');
const crypto = require('crypto');
const db = require('./db');
const logger = require('./logger');

const app = express();

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
  const incidentId = crypto.randomUUID();
  logger.error({ incidentId, err });

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({ error: 'Internal Server Error', incidentId });
});

module.exports = app;
```

## Explanation

**The route hands the error off rather than rendering it.** `next` is added to the handler signature and the `catch` block calls `next(error)`. Express skips the remaining normal middleware and dispatches to the four-argument error handler, which already produces a body with no attacker-usable detail. One response shape now covers every failure in the app, so a future route cannot reintroduce the leak by writing its own catch block.

**The `try/catch` stays.** On Express 4 a rejected promise from an `async` handler is not forwarded automatically - drop the `catch` and the request hangs until the client times out. Only Express 5 forwards rejections on its own, and keeping the explicit `catch` is correct under both. The change is what the `catch` does, not whether it exists.

**Logging moves to the handler and keeps the full error.** The route's `logger.error(error)` is removed because the middleware now logs every error that reaches it; leaving both in place would double-log this path. The middleware logs the whole `err` object - message, stack, and any cause - so nothing needed for diagnosis is lost. The trust boundary is the response body, not the log sink.

**`incidentId` preserves supportability.** Suppressing detail from the client usually costs the ability to correlate a user report with a log line. A random id returned to the caller and written alongside the log entry restores that link without revealing anything about the failure: it is generated per-error, carries no information derived from the exception, and is only meaningful to someone who can already read the logs. Use `crypto.randomUUID()` (Node 14.17+) rather than a counter or timestamp, which would expose request volume.

**`res.headersSent` guards the delegated path.** Once a route can forward errors, an error may arrive after a partial response has already been flushed - a stream that failed mid-write, for example. Writing a second set of headers throws `ERR_HTTP_HEADERS_SENT` inside the error handler. Deferring to `next(err)` lets Express's default handler destroy the socket, which is the only correct outcome at that point.

**Keep the error middleware registered last.** Express matches middleware in registration order, so any route or `app.use` added below it will not be covered. If the app is split across route modules, mount them all before this handler. Note also that Express's built-in fallback handler includes the stack in the response whenever `NODE_ENV` is not `production` - relying on that default rather than an explicit handler reintroduces this same finding in any environment where the variable is unset.

**Points to check nearby.** The `404` branch is already safe - `'not found'` is a fixed string and reveals nothing beyond the order's existence, which the endpoint's purpose implies. Worth confirming separately: that `db.js` and `logger.js` do not attach request parameters or connection strings to error objects that then reach a client-visible path elsewhere, and that no other route in the codebase repeats the `error.message` / `error.stack` pattern - grep for `\.stack` and `error.message` across the route layer, since this finding is usually one instance of a habit.

**Verify by** forcing `db.findOrder` to reject (a thrown error in a stub, or an invalid `:id` that trips the driver) and asserting the response body is exactly `{ error: 'Internal Server Error', incidentId: <uuid> }` with no `stack` key, while the log line for that `incidentId` still contains the full trace. Run it with `NODE_ENV` unset as well as set to `production`, since that is where the Express default-handler leak would show up.
