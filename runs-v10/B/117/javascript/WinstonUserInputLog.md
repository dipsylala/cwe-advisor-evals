## Verdict

The finding is valid. Untrusted user input (`username` from `req.body.username`) is directly interpolated into a logger call at line 19 without encoding, allowing log injection attacks.

## Source

`req.body.username` - untrusted HTTP request body parameter passed directly to the logging sink without validation or encoding.

## Fix

Add an encoding function and apply it to the `username` parameter before logging:

```javascript
const express = require('express');
const winston = require('winston');

const app = express();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [new winston.transports.Console()]
});

// Encode function to escape log injection characters
function encodeLogValue(value) {
  if (typeof value !== 'string') {
    value = String(value);
  }
  return value.replace(/[\x00-\x1f\x7f  \\]/g, (char) => {
    const code = char.charCodeAt(0);
    if (code === 0x5c) return '\\\\'; // backslash
    if (code < 0x20) return '\\x' + code.toString(16).padStart(2, '0');
    if (code === 0x7f) return '\\x7f';
    if (code === 0x0085) return '\\u0085';
    if (code === 0x2028) return '\\u2028';
    if (code === 0x2029) return '\\u2029';
  });
}

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;

  const user = findUserByUsername(username);
  if (!user) {
    logger.info(`Failed login attempt for user: ${encodeLogValue(username)}`);
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

The fix introduces an `encodeLogValue()` function that escapes all dangerous characters at the call site before logging. It targets the ASCII control range (0x00-0x1F), DEL (0x7F), Unicode line separators (U+0085, U+2028, U+2029), and the backslash itself. These characters are the attack surface for log injection: newlines and line separators forge additional log entries, null bytes truncate log analysis, and an unescaped backslash allows attackers to masquerade literal `\n` as a real newline. The encoding replaces each dangerous character with its escaped representation (e.g., a newline becomes `\x0a`), making it data rather than a log control sequence. This closes the injection vector and allows the log entry to preserve the full username for audit purposes.

## Behaviour changes

**Legitimate log entries with user-controlled data:**
- A login attempt with username `eve` logs: `Failed login attempt for user: eve` (unchanged)
- A login attempt with username `test\nFAKE` logs: `Failed login attempt for user: test\x0aFAKE` (backslash-n is escaped, preventing injection)
- A login attempt with username `test` + actual newline character logs: `Failed login attempt for user: test\x0a` (the injected newline is escaped)
- A login attempt with username containing U+2028 (Unicode line separator) logs the character as ` ` instead of as a raw separator that some parsers treat as a line terminator

**Sink behavior unchanged:**
- The logger receives a string with escaped control characters and logs it normally.
- The output still records the full username, just with control characters escaped so they appear literally in the log.
- Log aggregation systems and downstream parsers see properly escaped data and do not fork on injected terminators.

**Testing:**
- Injecting a newline (`test\nadmin login`) should produce `test\x0aadmin login` in the log (literal backslash-x-0-a, not a line break)
- A legitimate username containing a newline should be logged the same way - no special treatment, just escaped for safety
- Legitimate usernames with ASCII letters, digits, and common punctuation pass through unchanged
