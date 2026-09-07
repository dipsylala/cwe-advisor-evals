## Verdict
exploitable

## Source
`req.body.username` - untrusted user input from HTTP request body

## Fix

**Vulnerable code:**
```javascript
app.post('/login', (req, res) => {
  const username = req.body.username;
  const user = findUserByUsername(username);
  if (!user) {
    // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
    logger.info(`Failed login attempt for user: ${username}`);  // Vulnerable: direct interpolation
    return res.status(401).json({ error: 'invalid credentials' });
  }
  res.json({ status: 'ok' });
});
```

**Fixed code:**
```javascript
function encodeLogValue(value) {
  if (typeof value !== 'string') {
    return value;
  }
  let result = '';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x5C) { // backslash
      result += '\\\\';
    } else if (code < 0x20 || code === 0x7F || code === 0x85 || code === 0x2028 || code === 0x2029) {
      if (code < 0x20) {
        result += '\\x' + ('0' + code.toString(16)).slice(-2);
      } else if (code === 0x7F) {
        result += '\\x7F';
      } else if (code === 0x85) {
        result += '\\u0085';
      } else if (code === 0x2028) {
        result += '\\u2028';
      } else if (code === 0x2029) {
        result += '\\u2029';
      }
    } else {
      result += value[i];
    }
  }
  return result;
}

app.post('/login', (req, res) => {
  const username = req.body.username;
  const user = findUserByUsername(username);
  if (!user) {
    logger.info(`Failed login attempt for user: ${encodeLogValue(username)}`);
    return res.status(401).json({ error: 'invalid credentials' });
  }
  res.json({ status: 'ok' });
});
```

## Explanation
The vulnerability occurs because the untrusted `username` value from the HTTP request body is directly interpolated into the log message without encoding. An attacker can inject newlines, null bytes, or Unicode line separators to forge log entries, truncate records, or manipulate log output appearance. The fix encodes the value at the call site before logging by escaping the backslash, the ASCII control range (0x00-0x1F, 0x7F), and Unicode line separators (U+0085, U+2028, U+2029). This ensures that an attacker's input characters are rendered as escaped sequences (e.g., `\x0a` for newline), preventing log injection regardless of the logging transport or formatter in use.

## Behaviour changes
None. The fix adds an encoding function that escapes dangerous characters while preserving the original username value semantically. Legitimate usernames with ordinary punctuation or non-ASCII characters that do not require escaping pass through unchanged, and logging output remains valid and readable.
