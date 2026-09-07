## Verdict
Confirmed - CWE-117 (Improper Output Neutralization for Logs) at line 16. The f-string interpolation of user-controlled `username` into a log message allows log injection attacks.

## Source
The vulnerability originates from the `username` parameter obtained via `request.form.get("username", "")` at line 11, which flows untrusted user input into the log message at line 16 without neutralization.

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
The fix replaces the f-string interpolation with parameterized logging using `%s` placeholder and passing `username` as a separate argument to `logger.warning()`. Python's logging framework handles parameterized arguments safely by treating them as data rather than format strings, preventing injection of newlines, log level markers, or other metadata that could manipulate log output. This is the safe pattern for all logging methods in Python: `logger.warning(msg, arg1, arg2, ...)` instead of `logger.warning(f"{msg} {arg1} {arg2}")`.
