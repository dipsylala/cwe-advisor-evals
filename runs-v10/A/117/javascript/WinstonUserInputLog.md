## Verdict
Confirmed. User-controlled input (`username` from `req.body.username`) is logged directly without sanitization, allowing log injection via control characters like newlines.

## Source
```javascript
const username = req.body.username;

const user = findUserByUsername(username);
if (!user) {
  logger.info(`Failed login attempt for user: ${username}`);
```

The `username` parameter from the request body flows directly into the log statement.

## Fix
```javascript
const express = require('express');
const winston = require('winston');

const app = express();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [new winston.transports.Console()]
});

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;

  const user = findUserByUsername(username);
  if (!user) {
    const sanitizedUsername = String(username).replace(/[\n\r\t]/g, ' ');
    logger.info(`Failed login attempt for user: ${sanitizedUsername}`);
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
Neutralize the user-controlled input before logging by replacing newline (`\n`), carriage return (`\r`), and tab (`\t`) characters with spaces. These control characters are the primary vectors for log injection, where an attacker embeds them to create fake log entries that appear to come from the logger itself. The `String()` coercion ensures the value is a string before replacement, preventing errors if `username` is null or undefined. This preserves the username value for debugging while preventing it from breaking the log line structure.
