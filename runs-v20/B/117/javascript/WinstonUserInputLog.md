## Verdict

Exploitable. Confidence: high.

- CWE: CWE-117 (Improper Output Neutralization for Logs)
- Location: `WinstonUserInputLog.js`, line 19 (sink), inside the `POST /login` handler

## Source

`req.body.username` - the JSON request body field submitted by the client to `POST /login`. It is read at line 14 into `username` with no validation, encoding, or type check, then passed straight to `findUserByUsername`, and (regardless of the lookup result) into the log call. It is fully attacker-controlled: any string, including one containing newlines, other ASCII control characters, or Unicode line separators.

Sink: `logger.info(\`Failed login attempt for user: ${username}\`)`. `logger` is a `winston.createLogger` instance configured with `format: winston.format.simple()`, which produces plain text (`level: message`), not JSON - so there is no serializer in this pipeline that would otherwise escape control characters. The username is interpolated directly into the message template with no encoding at the call site, so a value such as `admin\n[FAKE] Login success for user: admin` forges a second, fabricated log line in the console output.

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

// Encodes a value for safe inclusion in a plain-text log line: escapes ASCII
// control characters (0x00-0x1F, 0x7F), the Unicode line/paragraph separators
// (U+0085, U+2028, U+2029), and the backslash itself, so an attacker cannot
// forge newlines or additional log entries via the logged value. The Unicode
// separators are built from character codes at runtime rather than pasted as
// literal source characters, since a raw U+2028/U+2029 in source text is
// itself an illegal LineTerminator outside a properly escaped context.
const UNICODE_LOG_SEPARATORS = [0x85, 0x2028, 0x2029]
  .map(function (code) {
    return String.fromCharCode(code);
  })
  .join('');
const LOG_UNSAFE_CHARS = new RegExp('[\\x00-\\x1F\\x7F' + UNICODE_LOG_SEPARATORS + '\\\\]', 'g');

function encodeForLog(value) {
  return String(value).replace(LOG_UNSAFE_CHARS, function (ch) {
    if (ch === '\\') {
      return '\\\\';
    }
    if (ch === '\n') {
      return '\\n';
    }
    if (ch === '\r') {
      return '\\r';
    }
    if (ch === '\t') {
      return '\\t';
    }
    var code = ch.charCodeAt(0);
    return code <= 0xFF
      ? '\\x' + code.toString(16).padStart(2, '0')
      : '\\u' + code.toString(16).padStart(4, '0');
  });
}

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

The logger's format (`winston.format.simple()`) is plain text, so nothing downstream escapes control characters, newlines, or Unicode line separators before they reach the console transport - the finding is real and the fix has to encode at the call site rather than rely on the formatter. `encodeForLog` replaces the raw `username` interpolation with an encoded copy: it escapes the ASCII control range (`0x00`-`0x1F`), `DEL` (`0x7F`), the Unicode separators `U+0085`/`U+2028`/`U+2029`, and the backslash character itself, each to a visible `\xHH`/`\uHHHH`/named escape. Encoding the backslash first (within the same single-pass `replace`, so the escaped output is never rescanned) is what stops a literal `\` + `n` typed by an attacker from rendering identically to a real encoded newline - the real newline becomes `\n` while the two-character input becomes `\\n`, and the two stay visually distinct. Ordinary characters, including non-ASCII text such as accented letters, pass through unchanged, so legitimate usernames still read correctly. The change is scoped to the one reported sink; the file has no other logging call to fix.

## Behaviour changes

- The logged message for a failed login now contains the encoded form of `username` instead of the raw value whenever it contains a control character, Unicode separator, or backslash; for any username without those characters (the common case) the log output is byte-for-byte identical to before. This is the intended effect of the fix, not a side effect.
- No change to `logger.info`'s arguments beyond the interpolated value, its return value (unused by the caller), the `winston` configuration (level, format, transports), the HTTP response (`res.status(401).json(...)` / `res.json(...)`), or `findUserByUsername`'s behavior.
- No new dependencies. `encodeForLog` uses only standard JS (`String.fromCharCode`, `RegExp`, `Array.prototype.map`/`join`, `String.prototype.replace`/`charCodeAt`, `Number.prototype.toString(16)`, `String.prototype.padStart`), all already available in the Node/Express environment the file already runs in.

Verification: copied the fixed file to a scratch directory and ran `node --check` against it - passed with no output. Also loaded the extracted `encodeForLog` function under plain Node and exercised it directly: a payload containing a real newline, `U+2028`, and `DEL` (`\n[FAKE] Login success for user: admin ...`) encoded to `\n`, ` `, and `\x7f` respectively with no raw control/separator characters remaining; an ordinary username (`normal.user-name_123`) and a non-ASCII-but-safe string (`café`) passed through unchanged; and a lone backslash followed by a literal `n` encoded to two backslashes followed by `n` (`\\n`, distinct from the single-backslash `\n` produced by a real newline), confirming the ambiguity the guidance warns about is closed.
