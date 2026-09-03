## Verdict

Confirmed. Untrusted HTTP form input (`username`) flows directly into a log message via f-string interpolation without encoding.

## Source

`request.form.get("username", "")` — HTTP POST parameter, attacker-controlled.

## Fix

**Vulnerable code** (line 16):
```python
logger.warning(f"Failed login attempt for user: {username}")
```

**Fixed code**:
```python
import json
import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("auth")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not authenticate(username, password):
        logger.warning("Failed login attempt for user: %s", json.dumps(username))
        return "Invalid credentials", 401

    return "Welcome", 200


def authenticate(username: str, password: str) -> bool:
    return username == "admin" and password == "correct-horse-battery-staple"
```

## Explanation

The fix replaces f-string concatenation with parameterized logging and encodes the username using `json.dumps()` before passing it to the logger. `json.dumps()` escapes all ASCII control characters (0x00–0x1F), DEL (0x7F), and Unicode line separators (U+0085, U+2028, U+2029) as escape sequences. This prevents log injection by rendering malicious newlines, CRLF sequences, and other control characters as escaped literals rather than structural characters. The parameterized message (`%s`) separates the log template from the data, allowing the logging framework to handle encoding consistently. An attacker injecting `admin\nFAKE` as the username now produces a log entry containing the literal escaped string `"admin\\nFAKE"` instead of forging a new log line.

## Behaviour changes

The logged username is now JSON-encoded, so it appears with quotes and escape sequences (e.g., user input `test"user` logs as `"test\"user"`). This is the correct and necessary encoding—it prevents injection while preserving the original value for audit purposes.
