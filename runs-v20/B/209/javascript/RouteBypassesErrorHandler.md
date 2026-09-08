## Verdict

- CWE-209: Generation of Error Message Containing Sensitive Information
- Location: `RouteBypassesErrorHandler.js:17`
- Verdict: exploitable
- Confidence: high

## Source

Any exception thrown inside the route's `try` block (for example a failure inside `db.findOrder(req.params.id)`) is caught into `error` at line 14. That `error` object - its `message` and full `stack` - is the tainted value; it originates from the application/runtime, not from user input, but its contents (stack frames, file paths, and for a database failure potentially driver/engine/query detail) are internal implementation detail that must not reach the client.

Sink: line 17, `return res.status(500).json({ error: error.message, stack: error.stack });` - this serializes the exception's message and full stack trace directly into the HTTP JSON response body.

The file already defines a centralized error-handling middleware (lines 21-24) that returns a generic `Internal Server Error` message. That middleware never runs for this route: the route's own `catch` block builds and sends the response itself, so control never reaches `next()`, and Express's error-handling middleware chain is bypassed entirely.

## Fix

### File: RouteBypassesErrorHandler.js

```javascript
const express = require('express');
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
  logger.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
```

## Explanation

The route's `catch` block no longer builds or sends a response itself; it forwards the caught error to Express via `next(error)`, giving the route handler a third (`next`) parameter so it can do so. Express routes an argument passed to `next()` straight to the nearest error-handling middleware, which is the four-argument `app.use((err, req, res, next) => ...)` handler already defined lower in the file. That handler logs the full error server-side with `logger.error(err)` and returns only the fixed, generic `{ error: 'Internal Server Error' }` body with a 500 status - so the client never receives `error.message` or `error.stack`, while the detail needed for debugging is still captured in the logs. This also removes the duplicate `logger.error(error)` call that used to run in the route itself, since the centralized handler now performs that logging on every path.

## Behaviour changes

- Response body on failure changes from `{ error: error.message, stack: error.stack }` to `{ error: 'Internal Server Error' }`. This is the intended fix - the discarded detail (message/stack) is exactly the information the finding requires not to reach the client.
- The 500 status code on the failure path is preserved (both the route's original response and the centralized handler return `res.status(500)`), so no client that inspects status codes is affected.
- Error logging moves from an inline `logger.error(error)` call in the route to the single `logger.error(err)` call already present in the centralized handler; the error is still logged exactly once, with the same log level and full detail, just from one place instead of two.
- The 404 "not found" path is untouched - it does not go through `catch`/`next` and its response body and status are unchanged.
- Verification: `node --check` was run against the fixed file (copied to a scratch location, not the fixture) and reported no syntax errors.
