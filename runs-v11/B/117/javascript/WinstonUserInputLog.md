## Verdict

Confirmed. Untrusted input `username` from `req.body` is logged without encoding, allowing log injection via control characters and newline injection.

## Source

`req.body.username` (line 14) - HTTP request parameter, attacker-controlled. Passed directly to logging sink at line 19 without validation or encoding.

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

// Helper function to encode untrusted input for logs
function encodeForLog(str) {
  if (typeof str !== 'string') str = String(str);
  return str
    .replace(/\\/g, '\\\\')                                      // Backslash first
    .replace(/[\x00-\x1f\x7f  ]/g, c => {       // Control chars and separators
      const map = {
        '\x00': '\\x00', '\x01': '\\x01', '\x02': '\\x02', '\x03': '\\x03',
        '\x04': '\\x04', '\x05': '\\x05', '\x06': '\\x06', '\x07': '\\x07',
        '\x08': '\\x08', '\x09': '\\x09', '\x0a': '\\x0a', '\x0b': '\\x0b',
        '\x0c': '\\x0c', '\x0d': '\\x0d', '\x0e': '\\x0e', '\x0f': '\\x0f',
        '\x10': '\\x10', '\x11': '\\x11', '\x12': '\\x12', '\x13': '\\x13',
        '\x14': '\\x14', '\x15': '\\x15', '\x16': '\\x16', '\x17': '\\x17',
        '\x18': '\\x18', '\x19': '\\x19', '\x1a': '\\x1a', '\x1b': '\\x1b',
        '\x1c': '\\x1c', '\x1d': '\\x1d', '\x1e': '\\x1e', '\x1f': '\\x1f',
        '\x7f': '\\x7f', '': '\\u0085', ' ': '\\u2028', ' ': '\\u2029'
      };
      return map[c];
    });
}

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;

  const user = findUserByUsername(username);
  if (!user) {
    logger.info(`Failed login attempt for user: ${encodeForLog(username)}`);
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

Added an `encodeForLog()` helper function that escapes all characters that can forge or break log entries: the ASCII control range (0x00-0x1F), DEL (0x7F), Unicode line separators (U+0085, U+2028, U+2029), and backslash. Applied it to the `username` parameter before logging at line 19. This prevents newline injection (where an attacker types `\n` or actual newline bytes to create fake log entries) and other control-character attacks that manipulate log analysis tools. The encoding preserves the original username for audit purposes while neutralizing special characters.

## Behaviour changes

- Log entries now display control characters and Unicode separators as literal escape sequences (e.g., a newline in the username appears as `\x0a`) instead of rendering as actual control characters that forge new log lines.
- Usernames containing legitimate punctuation, non-ASCII text, and whitespace (spaces, tabs) continue to log correctly; only control characters and separators are escaped.
- Attack payloads that inject newlines (e.g., `admin\nAdmin login succeeded`) now appear in the logs as escaped text and cannot create false audit entries.
