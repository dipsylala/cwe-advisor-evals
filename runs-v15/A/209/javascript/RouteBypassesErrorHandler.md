## Verdict

The code directly exposes error details (message and stack) to the client response, disclosing sensitive information about the application's internals and structure.

## Source

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

Line 17 returns both `error.message` and `error.stack` to the client, exposing implementation details.

## Fix

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
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
```

Return a generic error message to the client instead of exposing the actual error message or stack trace.

## Explanation

Error messages and stack traces can reveal sensitive information about your application's internals: file paths, library versions, code structure, and database details. Attackers use this information to craft targeted attacks.

The fix preserves full error logging server-side via `logger.error(error)` for debugging and monitoring, while returning a generic message to the client. This approach maintains operational visibility for developers and system administrators without disclosing implementation details to users.

The application already has a global error handler (lines 21-24) that uses this same pattern—returning a generic error message—making this local handler consistent with the framework's intended error handling strategy.
