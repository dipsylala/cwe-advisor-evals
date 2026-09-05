## Verdict
exploitable

## Source
`username = request.form.get("username", "")` at line 11 — untrusted HTTP form parameter

## Fix
**Vulnerable code (line 16):**
```python
logger.warning(f"Failed login attempt for user: {username}")
```

**Fixed code:**
```python
logger.warning("Failed login attempt for user: %s", repr(username))
```

## Explanation
The original code uses an f-string to interpolate the untrusted `username` value directly into the log message. An attacker who submits a username containing newlines (e.g., `"admin\nINFO: Login successful"`) can inject forged log entries. The fixed code uses parameterized logging with `repr()` encoding: `repr()` escapes all control characters (including newlines, null bytes, and Unicode line separators) so they appear as literal escape sequences in the log output rather than as actual control characters. This prevents an attacker's injected newline or other control character from breaking the log line or forging entries. The parameterized call separates the message template from the value, allowing the logging framework to apply encoding consistently.

## Behaviour changes
The output format changes from f-string interpolation to parameterized logging. The username value will now display with single quotes and escape sequences (e.g., `'admin\nFAKE'` instead of a bare `admin` with a line break). This is a necessary change to neutralize the injection vector: control characters are now rendered as readable escape sequences so they cannot be misinterpreted as log structure by log parsers or readers.
