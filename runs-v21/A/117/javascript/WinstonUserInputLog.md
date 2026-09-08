## Verdict
CONFIRMED. Line 19 logs user-controlled input directly in a string interpolation without sanitization, allowing log injection attacks.

## Source
The vulnerability occurs at line 19 in the express request handler. The `username` parameter originates from untrusted user input via `req.body.username` (line 14) and is directly interpolated into the log message without any sanitization or encoding.

## Fix
### File: WinstonUserInputLog.js
```javascript
const express = require('express');
const winston = require('winston');

const app = express();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;

  const user = findUserByUsername(username);
  if (!user) {
    // Use structured logging with username as separate metadata instead of string interpolation
    logger.info('Failed login attempt', { username });
    return res.status(401).json({ error: 'invalid credentials' });
  }

  res.json({ status: 'ok' });
});

function findUserByUsername(username) {
  return null;
}

module.exports = app;
```

## Explanation
The fix uses Winston's structured logging approach by passing `username` as separate metadata in the log call: `logger.info('Failed login attempt', { username })` instead of interpolating it into the message string. This approach:

1. **Prevents log injection** — User input is stored as structured metadata, not as part of the log message string, so newlines, ANSI codes, and other control characters cannot forge or manipulate the log output.

2. **Improves parsability** — The JSON format (specified in the logger configuration change from `simple()` to `json()`) separates the message from metadata, making logs easier to parse programmatically and search in log aggregation systems.

3. **Maintains context** — The username is still recorded for debugging and security auditing, but in a safe, structured way.

This is the recommended pattern for Winston when logging untrusted user input.
