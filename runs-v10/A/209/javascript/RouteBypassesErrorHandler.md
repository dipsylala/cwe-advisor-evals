## Verdict
CWE-209 confirmed. Line 17 exposes the full error object—including `error.message` and `error.stack`—in the HTTP response body, revealing sensitive implementation details such as stack traces and internal error context to clients.

## Source
Line 17 in the catch block returns error details directly to the HTTP response:
```javascript
return res.status(500).json({ error: error.message, stack: error.stack });
```

The error object is exposed as a response property, allowing stack traces and internal message content to leak to clients.

## Fix
Replace the exposed error object with a generic, non-informative error message:

```javascript
} catch (error) {
  logger.error(error);
  return res.status(500).json({ error: 'Internal Server Error' });
}
```

Alternatively, use a generic message that does not reference specific system details:

```javascript
} catch (error) {
  logger.error(error);
  return res.status(500).json({ error: 'An unexpected error occurred' });
}
```

## Explanation
The vulnerability occurs because error objects in JavaScript contain sensitive properties: `message` reveals implementation-specific error context, and `stack` exposes the complete call chain including file paths, function names, and internal application structure. This information aids attackers in reconnaissance and discovering security flaws.

The fix logs the full error (line 15, via `logger.error(error)`) to preserve error details for debugging and monitoring, while the HTTP response returns only a generic message that provides no technical insight to clients. This pattern allows operators to diagnose issues through logs while preventing information exposure to end users.

The application also defines a global error handler (lines 21–24) that demonstrates the correct pattern: it returns a generic `'Internal Server Error'` message without exposing error internals.
