## Verdict

Exploitable

## Source

`error` object captured in the catch block (line 14) from the exception raised by `db.findOrder(req.params.id)`.

## Fix

**Vulnerable code (line 7-19):**
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
    return res.status(500).json({ error: error.message, stack: error.stack });
  }
});
```

**Fixed code:**
```javascript
app.get('/orders/:id', async (req, res, next) => {
  try {
    const order = await db.findOrder(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'not found' });
    }
    return res.json(order);
  } catch (error) {
    logger.error(error);
    next(error);
  }
});
```

## Explanation

The route's catch block directly returns `error.message` and `error.stack` to the client, exposing internal implementation details, database error messages, file paths, and stack traces that attackers can leverage to understand the application architecture. The fix forwards the error to the centralized error handler middleware via `next(error)`, which is already defined below at lines 21-24. The centralized handler logs the full error server-side while returning only a generic "Internal Server Error" message to the client, ensuring sensitive diagnostic information never reaches the user.

## Behaviour changes

- Route handler signature now includes `next` parameter to enable error forwarding
- Catch block no longer sends a direct HTTP response; instead it passes control to error middleware via `next(error)`
- Client response changes from detailed error object `{ error: error.message, stack: error.stack }` to generic message `{ error: 'Internal Server Error' }` (delegated to centralized handler)
- Stack trace and exception details remain in server logs via `logger.error(error)` but are no longer transmitted to client
