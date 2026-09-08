## Verdict

**Confirmed Exploitable**. Untrusted `host` parameter flows from user JSON payload directly into shell command string via `os.system()` string formatting, allowing arbitrary command execution.

## Source

Line 14: `target_host = payload.get("host", "").strip()` - untrusted JSON parameter

## Fix

Replace `os.system()` string formatting with `subprocess.run()` argument array to eliminate shell interpretation. Pass `target_host` as a distinct list element so it cannot break out of its position.

### File: OsSystemStringFormat.py

```python
"""Network diagnostics endpoint for the internal admin dashboard."""

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
        subprocess.run(["ping", "-c", "4", target_host],
                       stdout=log_file,
                       stderr=subprocess.STDOUT)

    with open(log_path, "r") as log_file:
        output = log_file.read()

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
```

## Explanation

The original code passed `target_host` into a shell command string via `os.system()`, allowing shell metacharacters to break out. The fix replaces this with `subprocess.run()` using a list-form command where `target_host` becomes a distinct positional argument, not part of a parsed string. With `shell=False` (the default), the `ping` binary receives `target_host` as a literal argument that cannot contain shell operators. The output redirection moves from shell `>` operator to Python's file handling: `stdout=log_file` writes directly to the file, and `stderr=subprocess.STDOUT` merges stderr into stdout as the original did with `2>&1`. The subsequent read from the log file preserves the original behavior of returning captured output.

## Behaviour changes

**None.** The endpoint still executes `ping -c 4` against the supplied host and returns the captured output. The log file is still created at the same path with the same content. Exit codes are still ignored (subprocess does not raise on nonzero exit without `check=True`). Stdout and stderr are still merged in the output.
