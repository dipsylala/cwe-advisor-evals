## Verdict

Exploitable. `req.body.username` is attacker-controlled HTTP input that reaches a winston logging sink via unencoded string interpolation, with no validation or encoding anywhere on the path.

## Source

`req.body.username` (line 14), read from the JSON-parsed body of the `POST /login` request. `findUserByUsername` (a stub that always returns `null`) does not constrain or transform the value before the failed-login branch is taken, so the raw request field reaches the sink unchanged whenever the endpoint is called.

## Fix

Vulnerable code (line 19):

```javascript
    // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
    logger.info(`Failed login attempt for user: ${username}`);
```

Fixed code:

```javascript
// Unicode line/paragraph separators (U+0085, U+2028, U+2029) are built via fromCharCode
// rather than written as escapes, purely so they render as visible codes in this diff.
const UNICODE_LINE_SEPARATORS = String.fromCharCode(0x85, 0x2028, 0x2029);
const CONTROL_CHAR_RE = new RegExp('[\\x00-\\x1F\\x7F' + UNICODE_LINE_SEPARATORS + '\\\\]', 'g');

function encodeForLog(value) {
  return String(value).replace(CONTROL_CHAR_RE, (ch) => {
    if (ch === '\\') return '\\\\';
    return '\\u' + ch.codePointAt(0).toString(16).padStart(4, '0');
  });
}

// ...

    logger.info(`Failed login attempt for user: ${encodeForLog(username)}`);
```

## Explanation

The logger is configured with `winston.format.simple()`, a plain-text formatter with no built-in escaping - unlike `winston.format.json()`, it does not run values through `JSON.stringify` and therefore neutralizes nothing in the interpolated value. `encodeForLog` closes the finding directly at the call site: it escapes the ASCII control range (0x00-0x1F), DEL (0x7F), the Unicode line/paragraph separators (U+0085, U+2028, U+2029), and the backslash itself, replacing each with its escaped representation (a literal backslash becomes two backslashes; the others become their four-hex-digit unicode-escape form). Escaping the backslash prevents an attacker-supplied literal backslash-n (two characters) from becoming visually indistinguishable from a real, encoded newline in the log output. Because each matched character is replaced independently in a single regex pass, there is no double-escaping between the backslash rule and the control-character rules. This is a call-site fix only; switching the formatter to `winston.format.json()` is a separate, durable change that would still leave DEL and the Unicode separators unescaped, so it is not offered here as a substitute.

## Behaviour changes

- Log output for a username containing any control character, DEL, a Unicode line/paragraph separator, or a backslash now renders as an escaped sequence instead of the raw byte/character. This is the intended effect of the fix - it prevents forged log entries - and is limited to malicious/anomalous input; ordinary usernames (letters, digits, common punctuation) are logged identically to before.
- No change to control flow, the HTTP response (`res.status(401).json(...)` is untouched), the logger's configuration, or any other sink - this file has only the one logging call, so no other line needed fixing.
