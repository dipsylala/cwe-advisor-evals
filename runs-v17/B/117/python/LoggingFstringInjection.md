## Verdict
exploitable

## Source
Line 11: `username = request.form.get("username", "")` — untrusted HTTP form parameter flows to the logging sink without encoding.

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
        logger.warning("Failed login attempt for user: %s", repr(username))
        return "Invalid credentials", 401

    return "Welcome", 200


def authenticate(username: str, password: str) -> bool:
    return username == "admin" and password == "correct-horse-battery-staple"
```

## Explanation
The fix replaces the f-string concatenation with parameterized logging and encodes the untrusted username using `repr()`. The original code logged `f"Failed login attempt for user: {username}"`, which concatenates the raw username directly into the message. An attacker controlling the username parameter can inject newlines or other control characters to forge log entries or hide malicious activity. The fix uses `logger.warning("Failed login attempt for user: %s", repr(username))` to separate the message template from the value, and `repr()` escapes all control characters (ASCII 0x00–0x1F, 0x7F, and Unicode line separators U+0085, U+2028, U+2029) as escape sequences, so injected newlines and other control characters render as literal escaped text in the log output, preventing entry forgery.

## Behaviour changes
The username will now appear as a Python string representation (with quotes and escape sequences visible) rather than raw text. For example, if a user enters `admin'`, it will be logged as `'admin\''` instead of `admin'`. This preserves evidence of injection attempts and prevents log entry forgery, with no impact on legitimate authentication logging.
