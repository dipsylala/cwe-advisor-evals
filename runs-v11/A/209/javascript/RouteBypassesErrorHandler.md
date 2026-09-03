## Verdict
CONFIRMED. Line 17 exposes the error message and stack trace directly to the client, violating CWE-209.

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

## Explanation
The route handler sends the raw error message and stack trace to the client, exposing internal application details that could aid attackers. Error messages often reveal framework versions, database schemas, file paths, and function names. The fix returns a generic error message to clients while preserving the full error details in server-side logging. This approach maintains debuggability for developers via logs while preventing information leakage to users. The application already demonstrates the correct pattern in its global error handler at lines 21-24, which uses the same generic response strategy.
