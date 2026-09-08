## Verdict

Exploitable. The vulnerability is confirmed on line 19 where untrusted user input from `req.body.username` is directly concatenated into a log message using template string interpolation without any encoding or validation.

## Source

`req.body.username` (line 14) - untrusted HTTP request body parameter passed through to the logging call without sanitization.

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

// Encode log values by escaping control characters that could forge log entries
function encodeForLog(str) {
  if (typeof str !== 'string') return str;

  let result = '';
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code === 0x5c) result += '\\\\';           // Backslash
    else if (code >= 0x00 && code <= 0x1f) result += '\\x' + code.toString(16).padStart(2, '0');
    else if (code === 0x7f) result += '\\x7f';    // DEL
    else if (code === 0x85) result += '\\u0085';  // NEL
    else if (code === 0x2028) result += '\\u2028'; // Line separator
    else if (code === 0x2029) result += '\\u2029'; // Paragraph separator
    else result += str[i];
  }
  return result;
}

app.post('/login', (req, res) => {
  const username = req.body.username;

  const user = findUserByUsername(username);
  if (!user) {
    // Encode username to prevent log injection
    const encodedUsername = encodeForLog(username);
    logger.info('Failed login attempt', { username: encodedUsername });
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

The fix closes CWE-117 by encoding the untrusted `username` value before it reaches the winston logger sink. The `encodeForLog()` function escapes all characters that could be used to forge log entries: the ASCII control range (0x00-0x1F), DEL (0x7F), and Unicode line separators (U+0085, U+2028, U+2029). The backslash itself is also escaped so that a literal backslash-n sequence cannot be confused with a real newline character.

The fix applies encoding at the call site (line 34), transforming the untrusted value into safe data before logging. The logger is also switched from `simple()` format to `json()` format as a secondary control—JSON serialization provides built-in escaping of ASCII control characters and quotes, but cannot escape DEL or the Unicode separators, making the call-site encoding the primary defence. The username is now passed as a separate field in the metadata object rather than interpolated into the message string, which maintains the separation between the message template and the data value.

## Behaviour changes

The format of log output changes from plain text to JSON. This is a necessary secondary control that improves log integrity and enables better parsing by log aggregation tools, though the call-site encoding above remains the primary fix that applies regardless of the backend's encoding capability. The logger will now emit structured JSON events rather than simple text lines, which may affect log parsing or monitoring systems downstream that expect the old format. Legitimate log entries with ordinary punctuation or non-ASCII text will still read correctly—the encoding only escapes control characters and separators that would otherwise forge new log entries.
