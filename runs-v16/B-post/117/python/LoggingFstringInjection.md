## Verdict

Confirmed exploitable. Untrusted user input flows directly into a log message via f-string concatenation without encoding, allowing log injection.

## Source

The `username` parameter originates from untrusted HTTP form input at line 11:
```
username = request.form.get("username", "")
```

An attacker controls this value entirely - it is read from the HTTP request form data with no prior validation or sanitization before reaching the logging sink at line 16.

## Fix

Line 16 (vulnerable):
```python
logger.warning(f"Failed login attempt for user: {username}")
```

Fixed code:
```python
logger.warning("Failed login attempt for user: %s", repr(username))
```

## Explanation

The fix replaces direct f-string concatenation with parameterized logging using the `%s` format placeholder and applies `repr()` to the username value. 

`repr()` encodes all control characters (ASCII 0x00-0x1F, 0x7F, and Unicode line separators U+0085/U+2028/U+2029) as escape sequences, and preserves the backslash itself as an escape sequence. This ensures that a literal newline, literal backslash-n, CRLF, or any other log-control character typed by an attacker appears in the log as its escaped representation rather than as a structural element that forges a new log entry.

Parameterized logging separates the message template from the value, allowing the logging framework to see the value as data rather than message content. Combined with encoding at the call site, this closes the injection vector.

## Behaviour changes

The logged message will include quotes and escape sequences when the username contains control characters or special characters. For example:
- Input `admin` logs as: `Failed login attempt for user: 'admin'`
- Input `admin\nFAKE` logs as: `Failed login attempt for user: 'admin\\nFAKE'` (the backslash and n are escaped, not interpreted as a newline)
- Input containing an actual newline character logs as: `Failed login attempt for user: 'admin\nFAKE'` (displayed as escaped newline, not a line break)

These cosmetic changes preserve auditability while eliminating injection. Legitimate usernames with punctuation, spaces, or non-ASCII characters continue to log correctly. The fix does not change authentication logic or application behavior - only log formatting.
