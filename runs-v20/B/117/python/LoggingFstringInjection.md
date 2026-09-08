## Verdict

exploitable

- cwe_id: CWE-117 (Improper Output Neutralization for Logs)
- location: `LoggingFstringInjection.py`, line 16 (sink); `username` originates at line 11
- confidence: high

## Source

`request.form.get("username", "")` at line 11 - an HTTP POST form field, fully attacker-controlled and never validated or encoded before use. It flows unchanged into `authenticate()` (comparison only, no sanitization) and directly into the f-string at line 16.

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

The f-string spliced the raw `username` form value into the log message, so an attacker submitting a value containing `\r`, `\n`, or other control characters could forge additional log lines or inject misleading entries into the `auth` logger. The fix does two things per the loaded CWE-117 guidance: it switches to a parameterized `%s` call so the message template and the value stay separate, and it wraps the value in `repr()` before logging, which renders any control character (including newline, carriage return, and non-printable bytes) as a visible, unambiguous escape sequence and quotes the string so its boundaries are clear. `repr()` also escapes a literal backslash, so an attacker typing the two characters `\` and `n` cannot be confused with a real newline in the resulting log line. This closes the reported sink without changing the function's return values, control flow, or the `authenticate()` comparison.

## Behaviour changes

- Log output format: the logged value now appears as a quoted, escaped Python string literal (e.g. `'alice'` instead of `alice`; a payload with a newline renders as `'alice\r\nFAKE LOG'` on one line instead of splitting into multiple lines). This is the intended effect of the fix - the log line is no longer forgeable - and is the only behavioural difference. HTTP responses, status codes, and the authentication decision are unchanged.
- No other differences: no arguments were added, dropped, or defaulted; no other sink in the file was touched (there is only the one logging call); return values and control flow are identical to the original.

## Verification

Ran `python -m py_compile` (via the pinned uv-managed CPython 3.13.12 interpreter, since a bare `python`/`python3` is not on PATH in this environment) against a scratch copy of the fixed file - compiled cleanly with no diagnostics. `repr` and `logging.Logger.warning(msg, *args)` are both Python standard-library builtins used in their documented forms (positional `%`-style args to `warning`), not new dependencies, so no import check was needed.

Assumptions: none - the language (Python/Flask) and the sink line were unambiguous from the provided file, and the fix follows `cwe/117/python/INDEX.md`'s explicit `repr()` + parameterization guidance directly.
