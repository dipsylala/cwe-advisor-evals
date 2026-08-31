## Verdict
True positive. User-controlled input is embedded directly into a log message via f-string without sanitization, enabling log injection attacks.

## Source
Line 16: `logger.warning(f"Failed login attempt for user: {username}")`

The `username` variable originates from `request.form.get("username", "")` on line 11, which is untrusted user input.

## Fix
Replace the f-string with parameterized logging:

```python
logger.warning("Failed login attempt for user: %s", username)
```

## Explanation
F-strings in logging statements embed the unsanitized value directly into the message string. An attacker can inject special characters, ANSI escape sequences, or newlines into the username field to manipulate log output, forge log entries, or obscure attack trails (log injection).

Python's logging module supports parameterized messages where format arguments are passed separately via `%s`, `%d`, or other placeholders. The logger handles proper escaping and ensures that special characters in user input cannot alter the log structure or introduce injection payloads. This is the standard and secure approach for logging untrusted data in Python.
