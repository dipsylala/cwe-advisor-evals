## Verdict
Confirmed CWE-78. The code constructs a shell command by string interpolation with unsanitized user input (`target_host`), allowing arbitrary OS command injection.

## Source
Line 21 in `OsSystemStringFormat.py`:
```python
os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))
```

The `target_host` parameter originates from user input in the Flask request (line 14) and is passed directly into a shell command string without validation or escaping.

## Fix

### File: OsSystemStringFormat.py

```python
"""Network diagnostics endpoint for the internal admin dashboard."""

import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/admin/diagnostics/ping", methods=["POST"])
def run_ping_diagnostic():
    """Run a connectivity check against a host supplied by the admin UI and
    return the captured output so support staff can see the raw result."""
    payload = request.get_json(silent=True) or {}
    target_host = payload.get("host", "").strip()

    if not target_host:
        return jsonify({"error": "host is required"}), 400

    log_path = "/var/log/diagnostics/ping_last.log"
    with open(log_path, "w") as log_file:
        subprocess.run(["ping", "-c", "4", target_host], stdout=log_file, stderr=subprocess.STDOUT)

    with open(log_path, "r") as log_file:
        output = log_file.read()

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
```

## Explanation
The vulnerability occurs because `os.system()` executes a shell command string, and shell metacharacters in `target_host` (such as `;`, `|`, `&`, or backticks) are interpreted as command separators or operators. An attacker can inject arbitrary commands—for example, `"; rm -rf / #` would execute the destructive command within the ping invocation.

The fix replaces `os.system()` with `subprocess.run()` and passes arguments as a list (`["ping", "-c", "4", target_host]`) rather than a shell string. When `shell=False` (the default), each list element is treated as a literal argument to the `ping` program, not as shell syntax. The user input cannot break out of its argument position.

Output redirection is handled by `subprocess.run()`'s `stdout` and `stderr` parameters: both are directed to the log file, replacing the shell redirection `> %s 2>&1`. This approach is both safer and more explicit about where output goes.
