## Verdict

Confirmed. The `username` value from `request.form.get("username", "")` is attacker-controlled and is written into the log record unneutralized at line 16, via an f-string passed to `logger.warning`. An attacker can submit a username containing carriage-return/newline sequences (or terminal control/escape sequences) to forge additional fake log lines, split fields a log parser relies on, or inject content that corrupts downstream log analysis / terminal display.

## Source

`username = request.form.get("username", "")` (line 11) — read directly from the POST body of the `/login` route with no length limit, character allowlist, or neutralization before it reaches the sink.

## Fix

```python
import logging
import re

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("auth")

_LOG_UNSAFE_CHARS = re.compile(r"[\r\n\t\x00-\x1f\x7f]")


def sanitize_for_log(value: str, max_len: int = 128) -> str:
    """Strip CR/LF and other control characters so a single value cannot
    forge extra log lines or inject control sequences into log output."""
    cleaned = _LOG_UNSAFE_CHARS.sub("", value)
    return cleaned[:max_len]


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not authenticate(username, password):
        logger.warning("Failed login attempt for user: %s", sanitize_for_log(username))
        return "Invalid credentials", 401

    return "Welcome", 200


def authenticate(username: str, password: str) -> bool:
    return username == "admin" and password == "correct-horse-battery-staple"
```

## Explanation

The fix does two things, and only the first is the actual security control:

1. **Neutralize before logging.** `sanitize_for_log()` strips CR, LF, tab, other ASCII control characters (`\x00-\x1f`, `\x7f`), and caps the length before the value is ever handed to the logger. This is what closes CWE-117: an attacker can no longer embed `\r\n` sequences to fabricate additional log entries (e.g. `admin\nINFO: user admin authenticated successfully`) or inject terminal escape codes into log viewers. Stripping rather than escaping is deliberate — escaping (e.g. replacing `\n` with `\\n`) would also be acceptable, but stripping avoids any downstream ambiguity about whether the escaped sequence should be reinterpreted.

2. **Switch from an f-string to `%s`-style lazy formatting.** This is a secondary hygiene fix, not the vulnerability fix itself: with an f-string, `username` is interpolated into the message eagerly at the call site regardless of whether the `WARNING` level is enabled, and any malicious content is already baked into the string before `logging` ever sees it. Passing `username` as a positional logging argument defers formatting to the logging module and keeps the raw value available to log-record processors (handlers, filters) rather than only a pre-flattened string — but note that lazy formatting alone does **not** neutralize CR/LF; the sanitization step above is what does that work. Without it, `%s`-formatting would still let a newline through unchanged.

The same pattern should be applied anywhere else user input (headers, query params, form fields) is interpolated directly into a log message in this codebase.
