## Verdict

Exploitable.

## Source

`req.body.username` — attacker-controlled HTTP request body parameter from the POST `/login` endpoint (line 14).

## Fix

Encode the username value before logging it to prevent log injection attacks:

**Vulnerable code (line 19):**
```javascript
logger.info(`Failed login attempt for user: ${username}`);
```

**Fixed code:**
Add the encoding function at module scope:
```javascript
function encodeLogValue(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/[\x00-\x1F\x7F]/g, (ch) => {
      const code = ch.charCodeAt(0);
      const hex = code.toString(16).padStart(2, '0');
      switch (code) {
        case 8: return '\\b';
        case 9: return '\\t';
        case 10: return '\\n';
        case 12: return '\\f';
        case 13: return '\\r';
        default: return '\\x' + hex;
      }
    })
    .replace(/[\u0085\u2028\u2029]/g, (ch) => {
      const code = ch.charCodeAt(0);
      return '\\u' + code.toString(16).padStart(4, '0');
    });
}
```

Then update the logging call to use the encoder:
```javascript
logger.info(`Failed login attempt for user: ${encodeLogValue(username)}`);
```

## Explanation

The vulnerability allows an attacker to inject control characters (newlines, null bytes, carriage returns) or Unicode line separators into log output by supplying them in the username parameter. These characters can forge log entries, hide malicious activity, or manipulate log aggregation and analysis systems. The fix encodes the username before logging it, escaping the ASCII control range (0x00–0x1F, 0x7F), Unicode line separators (U+0085, U+2028, U+2029), and backslashes so that literal backslash-n and actual newlines render differently and control characters appear as escaped representations in the logs. This preserves the data for security review while preventing injection attacks. Winston's JSON formatter provides an additional secondary control by escaping quotes and backslashes during serialization, but call-site encoding is the primary and necessary defence.

## Behaviour changes

None. The encoding function returns a string with the same semantic content as the original username but with control characters escaped as visible representations. The log output format and structure remain unchanged; only the literal content of log entries changes to make injected characters visible rather than functional.
