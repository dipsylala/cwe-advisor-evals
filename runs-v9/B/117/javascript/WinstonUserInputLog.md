## Verdict

- **CWE ID**: CWE-117 (Improper Output Neutralization for Logs)
- **Location**: `WinstonUserInputLog.js`, line 19 (`logger.info` call)
- **Verdict**: exploitable
- **Confidence**: high

The trace shows a direct, unbroken path from the HTTP request body to an unencoded winston log call. No validation, allowlist, or encoding step sits between the two.

## Source

`req.body.username` at line 14 - the JSON-parsed body of the `POST /login` request (via `express.json()`), fully attacker-controlled. `findUserByUsername` returns `null` unconditionally in this file, so the `if (!user)` branch containing the sink is always reached for any submitted username, including one crafted to inject log-control characters.

## Fix

No library change is needed: the app already uses winston, which is the guidance's preferred choice over bunyan. The logger is configured with `winston.format.simple()` (plain text, not JSON), so `JSON.stringify`-based escaping does not apply here at all - the value must be encoded explicitly at the call site.

Vulnerable code (line 19):

```js
    // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
    logger.info(`Failed login attempt for user: ${username}`);
```

Fixed code:

```js
// Escapes ASCII control chars, DEL, the Unicode line/paragraph separators, and
// backslash itself, so a literal "\n" and a real newline can't render identically
// in the log output. Escape sequences are written as JS character codes (not
// pasted as literal characters) since a raw U+2028/U+2029 inside a regex literal
// is itself an illegal LineTerminator and throws a SyntaxError.
const LOG_UNSAFE_RE = new RegExp(
  '[\\x00-\\x1F\\x7F\\u0085\\u2028\\u2029\\\\]',
  'g'
);

function encodeLogValue(value) {
  return String(value).replace(LOG_UNSAFE_RE, (ch) => {
    if (ch === '\\') return '\\\\';
    return '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
  });
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

`encodeLogValue` is applied to `username` immediately before it is interpolated into the log message. It coerces the value to a string (matching the implicit coercion the original template literal already performed) and replaces every ASCII control character (0x00-0x1F, including ESC/0x1B used for ANSI colour codes), DEL (0x7F), the Unicode line/paragraph separators (U+0085, U+2028, U+2029), and the backslash character itself with a visible `\uXXXX` escape. Escaping the backslash is what prevents an attacker-submitted literal backslash-n from becoming indistinguishable from a real injected newline once escaped. Because `winston.format.simple()` performs no encoding of its own, this call-site fix is what closes the finding regardless of the configured transport; moving to `winston.format.json()` is a separate, broader change and was not made here, since JSON serialization would still leave DEL and the Unicode separators unescaped.

## Behaviour changes

- The logged value for `username` is now escaped when it contains control characters, backslashes, or the listed Unicode separators; ordinary usernames (letters, digits, punctuation, non-ASCII text) are logged unchanged, since `encodeLogValue` only touches the specific character set above.
- No change to the HTTP response: `res.status(401).json({ error: 'invalid credentials' })` is untouched, so client-visible behaviour is identical.
- No change to the logger's configuration, transport, level, or return-value handling - `logger.info()`'s return value is still discarded, as in the original.
- `none` beyond the above: the fix only wraps the interpolated value at the existing sink and does not alter arguments, add metadata fields, or change control flow.

**Assumptions**: `username` may be a non-string value from the parsed JSON body (number, object, etc.); `encodeLogValue` coerces via `String(value)`, which matches the implicit `ToString` the original template literal already applied, so this is not a behaviour change.
