## Verdict
exploitable

## Source
Exception thrown by `db.findOrder()` at line 9, propagates through the catch block where it is caught at line 14.

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
    logger.error(error);
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
The route handler was catching exceptions and directly exposing the error message and stack trace to the client via `res.status(500).json({ error: error.message, stack: error.stack })`. This violates CWE-209 by leaking sensitive information about the application's internal structure. The fix forwards the caught error to Express.js's centralized error handler middleware using `next(error)`, which is already configured to return a generic error message (`{ error: 'Internal Server Error' }`). The detailed error is still logged server-side via `logger.error(error)`, so debugging capability is preserved while client-facing responses remain generic and safe.

## Behaviour changes
The error response body now returns `{ error: 'Internal Server Error' }` instead of `{ error: <db-specific-message>, stack: <stack-trace> }`. The response status remains 500. The centralized error middleware is now invoked instead of the route handler sending the response directly. This is the intended behavior - a single point of error response control prevents accidental information leaks and ensures consistency across all routes.
