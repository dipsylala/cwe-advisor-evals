## Verdict

Exploitable OS Command Injection vulnerability confirmed.

## Source

Line 14: `target_host = payload.get("host", "").strip()`

The `target_host` value is extracted from the JSON request body without validation and originates from untrusted external input (the Flask request).

## Fix

```python
"""Network diagnostics endpoint for the internal admin dashboard."""

import re
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

    # Validate target_host to prevent argument injection (CWE-88)
    # Allow only alphanumeric characters, dots (for IPs), and hyphens (for hostnames)
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", target_host):
        return jsonify({"error": "invalid host format"}), 400

    # Use subprocess with argument list and shell=False to prevent command injection
    try:
        result = subprocess.run(
            ["ping", "-c", "4", target_host],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return jsonify({"error": "ping command timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"ping command failed: {str(e)}"}), 500

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
```

## Explanation

The vulnerability was caused by passing untrusted user input into `os.system()` via string formatting. An attacker could inject shell metacharacters (`;`, `|`, `&`, `$()`, backticks) to execute arbitrary commands.

The fix eliminates `os.system()` and replaces it with `subprocess.run()` using an argument list with `shell=False`. This separates the command from its arguments at the process invocation level, preventing shell interpretation. The command and each argument are passed separately as list elements: `["ping", "-c", "4", target_host]`. Even if `target_host` contains shell metacharacters, they are treated as literal argument data, not shell syntax.

Additionally, input validation using `re.fullmatch()` (not `re.match()`, which leaves `$` ambiguous) restricts `target_host` to valid hostname and IP address characters, preventing argument injection attacks (CWE-88) where a value like `--to-command=...` could inject flags into ping's argument list.

The original functionality is preserved: `subprocess.run()` with `capture_output=True` and `text=True` captures both stdout and stderr, combined and returned to the caller exactly as the original code did (reading from the log file).

## Behaviour changes

- **Error handling**: The original code would silently fail if the log file could not be written, or raise an unhandled exception if the directory did not exist. The fixed code explicitly catches `TimeoutExpired` (30-second timeout on ping) and generic exceptions, returning structured error responses with appropriate HTTP status codes (504 for timeout, 500 for other failures).
- **Timeout protection**: The original code had no timeout and could hang indefinitely if the target host was unreachable. `subprocess.run(..., timeout=30)` adds a 30-second timeout.
- **Input validation**: The original code accepted any string. The fixed code rejects input containing special characters outside the hostname/IP format, returning HTTP 400 (Bad Request) for invalid input.
- **No file I/O**: The original code redirected to a file and read it back. The fixed code eliminates this I/O layer and captures output directly via subprocess pipes, which is more reliable and avoids potential file permission or path traversal issues.
