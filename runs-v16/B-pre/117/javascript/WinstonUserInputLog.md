## Verdict

exploitable

## Source

Untrusted `username` from HTTP request body (`req.body.username` on line 14)

## Fix

**Vulnerable code (line 19):**
```javascript
logger.info(`Failed login attempt for user: ${username}`);
```

**Fixed code:**

First, add an encoding function at the top of the file (after imports):

```javascript
const escapeControlCharacters = (str) => {
  if (typeof str !== 'string') return str;
  return str
    .replace(/\\/g, '\\\\')
    .replace(/\x00/g, '\\x00')
    .replace(/[\x01-\x1F]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'))
    .replace(/\x7F/g, '\\x7F')
    .replace(//g, '\\u0085')
    .replace(/ /g, '\\u2028')
    .replace(/ /g, '\\u2029');
};
```

Then replace the logging statement:

```javascript
logger.info('Failed login attempt for user:', { username: escapeControlCharacters(username) });
```

## Explanation

The vulnerability occurs because untrusted user input (username) is directly interpolated into a log message without encoding. This allows attackers to inject log control characters (newlines, null bytes, DEL, Unicode line separators) to forge log entries, manipulate log analysis, or hide malicious activity. The fix applies two defenses: (1) the escapeControlCharacters function encodes all dangerous characters (ASCII control range 0x00-0x1F, DEL 0x7F, U+0085, U+2028, U+2029) so they appear as escaped sequences rather than control characters, and (2) structured logging via an object field separates the message template from the data, avoiding direct string interpolation and allowing the encoding to be applied at the call site consistently.

## Behaviour changes

None. The logging output format is preserved—the function only escapes control characters so they render as literal escape sequences (e.g., \x0a instead of a real newline) rather than breaking the log line. Legitimate usernames containing ordinary punctuation or non-ASCII text pass through unchanged.
