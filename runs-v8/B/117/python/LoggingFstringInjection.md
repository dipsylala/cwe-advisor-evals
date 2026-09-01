## Verdict

CONFIRMED - log injection via unencoded user input

## Source

The `username` parameter is obtained from untrusted user input (`request.form.get("username", "")`) and flows directly into the logging statement without encoding.

## Fix

Replace the f-string logging call with a parameterized message that encodes the value:

**Vulnerable code (line 16):**
```python
logger.warning(f"Failed login attempt for user: {username}")
```

**Fixed code:**
```python
logger.warning("Failed login attempt for user: %s", repr(username))
```

Alternatively, `json.dumps(username)` can be used instead of `repr(username)`, but `repr()` is simpler and does not require additional imports.

## Explanation

The fix converts the f-string to a parameterized message using `%` formatting and encodes the user-supplied value with `repr()`. This achieves two things:

1. **Encoding**: `repr()` escapes all control characters (ASCII 0x00-0x1F, 0x7F), backslashes, and Unicode line separators (U+0085, U+2028, U+2029). An attacker who types a newline character will see it rendered as `\n` in the log output, preventing log entry forging.

2. **Parameterization**: Using `%s` formatting separates the message template from the data value, allowing the logging framework to handle encoding independently if structured logging is added later.

By encoding at the call site, the fix closes the injection vector regardless of the logging backend configuration or handlers in use.

## Behaviour changes

- Newline characters in usernames now appear as literal `\n` in log output instead of creating line breaks
- Other control characters and Unicode separators are similarly escaped to their escape-sequence form
- Log entries remain readable and maintain audit trail integrity
- Legitimate usernames with punctuation or non-ASCII characters continue to display correctly (e.g., "user@example.com" remains fully visible, not stripped or truncated)
