## Verdict

CONFIRMED. The vulnerability is exploitable. Line 16 logs untrusted user input (`username`) via an f-string without encoding, allowing attackers to inject newline characters, CRLF sequences, or other control characters to forge log entries and hide malicious activity.

## Source

**Line 11:** `username = request.form.get("username", "")`  
Untrusted input from HTTP POST parameter, attacker-controlled.

**Line 16 (Sink):** `logger.warning(f"Failed login attempt for user: {username}")`  
Direct concatenation of untrusted `username` into f-string passed to `logger.warning()`.

**Data Flow:** HTTP POST parameter → `request.form.get()` → untrusted local variable → f-string interpolation → logging sink.

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

The f-string at line 16 has been replaced with parameterized logging using `logger.warning("Failed login attempt for user: %s", repr(username))`. The `repr()` function escapes all control characters (ASCII 0x00–0x1F, 0x7F, and Unicode separators U+0085/U+2028/U+2029) and renders them as escape sequences (e.g., a literal newline becomes `\n`, a typed backslash-n becomes `\\n`). This ensures that any injection payload appears as data, not as log control structures. The parameterized call separates the message template from the value, allowing the logger to handle encoding consistently. An attacker injecting `admin\nFAKE` will now produce output like `'admin\\nFAKE'` in the log, making the injection attempt visible rather than creating a forged log entry.

## Behaviour changes

- **Output format change:** The logged username will now appear as a Python string literal representation (e.g., `'username'` or `'user\nname'` if containing control characters) instead of the raw string. This is a necessary trade-off to prevent injection. Log parsing tools and incident responders benefit from seeing escape sequences rather than having the log structure silently corrupted by injected newlines.
- **No functional impact:** The fix does not change application behavior or authentication logic; only the log output format changes to secure it.
- **Compliance:** Closes CWE-117 at this sink. Any other logging statements in the application using untrusted input without encoding remain vulnerable and must be fixed separately.
