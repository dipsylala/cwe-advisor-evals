## Verdict

EXPLOITABLE. User input from `req.body.username` flows unsanitized to `logger.info()` via string interpolation, enabling log injection. An attacker can inject newlines, null bytes, Unicode line separators, or ANSI escape codes to forge log entries, hide activity, or disrupt log parsing.

## Source

HTTP request body parameter `username` at line 14: `const username = req.body.username;`

This value is attacker-controlled and arrives from the client without validation.

## Fix

```javascript
// Encoding function: escape characters that enable log injection
function encodeLogValue(value) {
  if (value == null) return '';
  const str = String(value);
  return str
    .replace(/\\/g, '\\\\')           // Backslash: escape first to prevent double-escaping
    .replace(/\x00/g, '\\x00')        // NULL
    .replace(/\x01/g, '\\x01')
    .replace(/\x02/g, '\\x02')
    .replace(/\x03/g, '\\x03')
    .replace(/\x04/g, '\\x04')
    .replace(/\x05/g, '\\x05')
    .replace(/\x06/g, '\\x06')
    .replace(/\x07/g, '\\x07')
    .replace(/\x08/g, '\\x08')
    .replace(/\x09/g, '\\x09')
    .replace(/\x0A/g, '\\n')          // LF (newline)
    .replace(/\x0B/g, '\\x0B')
    .replace(/\x0C/g, '\\x0C')
    .replace(/\x0D/g, '\\r')          // CR (carriage return)
    .replace(/\x0E/g, '\\x0E')
    .replace(/\x0F/g, '\\x0F')
    .replace(/\x10/g, '\\x10')
    .replace(/\x11/g, '\\x11')
    .replace(/\x12/g, '\\x12')
    .replace(/\x13/g, '\\x13')
    .replace(/\x14/g, '\\x14')
    .replace(/\x15/g, '\\x15')
    .replace(/\x16/g, '\\x16')
    .replace(/\x17/g, '\\x17')
    .replace(/\x18/g, '\\x18')
    .replace(/\x19/g, '\\x19')
    .replace(/\x1A/g, '\\x1A')
    .replace(/\x1B/g, '\\x1B')        // ESC (start of ANSI sequences)
    .replace(/\x1C/g, '\\x1C')
    .replace(/\x1D/g, '\\x1D')
    .replace(/\x1E/g, '\\x1E')
    .replace(/\x1F/g, '\\x1F')
    .replace(/\x7F/g, '\\x7F')        // DEL
    .replace(//g, '\\u0085')    // NEL (Next Line)
    .replace(/ /g, '\\u2028')    // Line Separator
    .replace(/ /g, '\\u2029');   // Paragraph Separator
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

The vulnerability occurs because `username` is concatenated directly into the log message without encoding. An attacker can supply a username containing newlines (`\n`), null bytes, Unicode line separators (U+2028, U+2029), or ANSI escape codes to forge additional log entries, hide malicious activity in log files, or break log parsing tools.

The fix introduces an `encodeLogValue()` function that escapes all characters in the ASCII control range (0x00-0x1F, 0x7F), Unicode line separators (U+0085, U+2028, U+2029), and the backslash itself. This ensures that literal backslash-n (two characters) cannot be confused with an actual newline (one character), and that injected control characters are recorded as visible escape sequences in the log, preserving both the audit trail and the evidence that an injection attempt occurred.

The encoding is applied at the call site before the value reaches `logger.info()`, ensuring it takes effect regardless of the logging transport or formatter configuration. While structured JSON logging (e.g., `winston.format.json()`) adds a secondary layer by escaping some control characters through `JSON.stringify`, it does not cover DEL (0x7F) or Unicode line separators, so call-site encoding remains necessary.

## Behaviour changes

**Changed behaviour:**
- A username containing control characters (newlines, tabs, null bytes, Unicode line separators, ANSI codes) now appears in logs as escaped sequences (e.g., `\n`, `\x00`, ` `) instead of as raw characters.
- The log output for such inputs expands slightly due to the escape sequences.

**Preserved behaviour:**
- Legitimate usernames with ordinary ASCII letters, digits, and punctuation (spaces, hyphens, underscores, periods, etc.) appear in logs unchanged—the encoding function preserves all printable ASCII characters.
- The logging call still uses string interpolation with the `logger.info()` API; no change to the logging framework.
- Error responses and the login flow remain identical; only the log content is sanitized.

**Security impact:**
- Log injection attacks are now prevented: injected newlines or control characters are visible as escape sequences, preventing forging of log entries.
- The audit trail is preserved: evidence that a malicious input was attempted is still recorded.
