## Verdict
Confirmed. User-controlled input (`username` from `request.form.get()`) is directly interpolated into a log message via f-string, allowing an attacker to inject log format codes, newlines, or other content that pollutes the log stream.

## Source
```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not authenticate(username, password):
        logger.warning(f"Failed login attempt for user: {username}")
        return "Invalid credentials", 401
```

An attacker submitting `username=admin%x%x%x` or `username=admin\n[FAKE ALERT]` in the POST request would inject log content that could mask real warnings or deceive log aggregation systems.

## Fix
```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not authenticate(username, password):
        logger.warning("Failed login attempt for user: %s", username)
        return "Invalid credentials", 401
```

## Explanation
Replace f-string interpolation with positional argument passing to the logger. The `logger.warning()` method (and all logging methods) accepts a message template followed by `%`-style format arguments. This approach keeps the message template as a compile-time string constant and passes the untrusted data separately as a logging argument, which the logging system processes safely. Format codes in the user-supplied `username` are treated as literal characters, not as format directives, and the logger's output filters prevent log injection. This is the standard defense for CWE-117 in Python logging.
