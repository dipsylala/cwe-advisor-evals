## Verdict

Confirmed OS Command Injection (CWE-78). The `target_host` parameter from user input is passed unsanitized into a shell command string via `os.system()`, allowing an attacker to inject arbitrary shell metacharacters and commands.

## Source

The vulnerability is on line 21 of `OsSystemStringFormat.py`:
```python
os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))
```

The `target_host` value comes directly from user input (`request.get_json()`) with only whitespace stripping applied. An attacker can pass shell metacharacters (`;`, `|`, `$()`, `` ` ``, `&`, etc.) to execute arbitrary commands on the system.

## Fix

Replace `os.system()` with `subprocess.run()` using an argument list. Passing arguments as a list prevents the shell from interpreting metacharacters in the data.

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

`os.system()` passes its argument to the shell, which interprets special characters. Using `subprocess.run()` with an argument list (as separate elements in a list rather than a concatenated shell string) passes the arguments directly to the `ping` executable without shell processing. Shell metacharacters in `target_host` are now treated as literal characters, not as command operators.

The fix redirects stdout and stderr to the log file using the `stdout` and `stderr` parameters of `subprocess.run()` instead of shell redirection operators, and opens the file in write mode to replace the previous log (equivalent to `>` in the shell).
