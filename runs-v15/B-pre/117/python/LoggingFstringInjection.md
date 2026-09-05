## Verdict

Real vulnerability. Untrusted HTTP form input is embedded directly into a log message via f-string without encoding, allowing attackers to inject newline characters to forge log entries or hide malicious activity in audit logs.

## Source

Line 11: `username = request.form.get("username", "")` — untrusted HTTP form parameter.

Line 16: `logger.warning(f"Failed login attempt for user: {username}")` — sink writes unencoded input to logs.

## Fix

Replace the f-string logging call with parameterized formatting and encode the untrusted value:

```python
logger.warning("Failed login attempt for user: %s", repr(username))
```

## Explanation

The fix separates the log message template from the untrusted data by using parameterized formatting (`%s` placeholder) instead of f-string concatenation. The `repr()` function encodes the username, converting all control characters (including newlines, tabs, null bytes) and the backslash itself into escape sequences. This ensures that even if an attacker injects `admin\nFAKE: login success`, the log entry will read literally as that string with escaped characters, not as two separate log lines. The parameterized approach also ensures the logging framework receives the message structure and data separately, allowing handlers to apply additional encoding if needed.

## Behaviour changes

- Log output for typical usernames: unchanged (letters, numbers, and common punctuation pass through repr() unmodified for readability).
- Log output for attack payloads: control characters like newlines are now escaped (e.g., `\n` instead of an actual newline), preventing log forgery and preserving the complete attack attempt in the audit trail for incident investigation.
- Performance: negligible (repr() is extremely fast, and parameterized logging is the standard Python logging pattern).
