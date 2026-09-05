## Verdict

CONFIRMED - The route handler at line 17 directly exposes the error object's `message` and `stack` properties to the client, leaking internal implementation details such as database error messages, file paths, and stack traces.

## Source

The `error` object caught from the `db.findOrder()` call in the try block (line 9), which can contain sensitive database or system error details.

## Fix

Replace the direct error object properties in the response with a generic error message:

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
    // Return generic error message to client, detailed error already logged
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
```

## Explanation

The vulnerability exists because line 17 sends `error.message` and `error.stack` directly to the client. Database connection errors, missing environment variables, file system errors, or other internal exceptions expose implementation details that help attackers understand the application's architecture and identify attack vectors.

The fix replaces the direct error properties with a static generic message. The detailed error has already been captured by `logger.error(error)` on line 15, so no diagnostic information is lost—it remains available server-side for monitoring and debugging. The client receives only the fact that an error occurred, without learning why or how the system is implemented.

This also brings the route's error handling in line with the centralized error middleware already defined (lines 21–24), which returns the same generic message. A centralized handler alone is insufficient because this route's `catch` block bypasses it; the fix ensures consistent, safe error responses across all code paths.

## Behaviour changes

- Error responses now return `{ error: "Internal Server Error" }` instead of exposing the underlying error's message and stack trace.
- HTTP status code remains 500 (unchanged).
- Detailed errors remain available server-side through the logger for monitoring and debugging.
- Client cannot distinguish between different failure modes (database error, missing order, internal exception) from the response alone, preventing error-based enumeration and information gathering.
