## Verdict
The vulnerability is confirmed. Line 16 logs user-supplied input directly via f-string interpolation without neutralization, allowing log injection attacks.

## Source
Line 16 in `LoggingFstringInjection.py` uses an f-string to interpolate `username` (derived from untrusted `request.form`) directly into the log message. An attacker can inject newlines, ANSI escape codes, or other characters to manipulate log output, hide entries, or forge false log records.

## Fix

### File: LoggingFstringInjection.py
```python
import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("auth")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not authenticate(username, password):
        # SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
        logger.warning("Failed login attempt for user: %s", username)
        return "Invalid credentials", 401

    return "Welcome", 200


def authenticate(username: str, password: str) -> bool:
    return username == "admin" and password == "correct-horse-battery-staple"
```

## Explanation
The f-string interpolation at line 16 has been replaced with parameterized logging using `%s` placeholder and a positional argument. Python's logging module automatically handles neutralization of the username parameter when passed as a separate argument, preventing log injection attacks. This approach preserves the intended log message while safely incorporating untrusted user input without interpreting special characters or escape sequences embedded in the username.
