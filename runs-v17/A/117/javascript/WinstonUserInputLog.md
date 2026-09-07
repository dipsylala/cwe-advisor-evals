## Verdict

CONFIRMED

## Source

User-controlled input from `req.body.username` on line 14 flows directly into a log statement on line 19 without sanitization.

## Fix

### File: WinstonUserInputLog.js

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
    // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
    logger.info('Failed login attempt for user', { username: username });
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

The vulnerability on line 19 logs unsanitized user input within a string interpolation. An attacker can inject newlines (`\n`), carriage returns (`\r`), or other control characters into the username to manipulate log output or inject false log entries.

The fix replaces string interpolation with Winston's structured logging format. Instead of `logger.info(`Failed login attempt for user: ${username}`)`, use `logger.info('Failed login attempt for user', { username: username })`. This passes the username as a separate data field rather than embedding it in the message string. Winston's formatters then handle the field safely, escaping or sanitizing control characters automatically and preventing log injection attacks.
