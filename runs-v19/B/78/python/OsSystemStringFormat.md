## Verdict

Real finding - confirmed exploitable. The target_host parameter from user input is directly interpolated into a shell command string passed to os.system(), allowing arbitrary OS command injection through shell metacharacters.

## Source

**Location**: OsSystemStringFormat.py, line 21

**Source data**: target_host from request.get_json() (line 14) - user-supplied JSON payload, stripped of whitespace but not validated

**Sink**: os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))

**Attack vector**: Attacker submits JSON with host value like "127.0.0.1; rm -rf /" to execute arbitrary commands on the system.

## Fix

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
    # Use subprocess.run with argument list and shell=False to prevent command injection
    result = subprocess.run(
        ['ping', '-c', '4', target_host],
        capture_output=True,
        text=True
    )
    
    # Write the combined stdout and stderr to the log file
    with open(log_path, 'w') as log_file:
        log_file.write(result.stdout)
        log_file.write(result.stderr)

    with open(log_path, "r") as log_file:
        output = log_file.read()

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
```

## Explanation

The fix replaces os.system() with subprocess.run() using an argument list and shell=False. In subprocess.run(['ping', '-c', '4', target_host], ...), the target_host is passed as a separate list element, preventing shell interpretation of metacharacters. The argument array prevents the shell parser from treating user input as command syntax. capture_output=True collects both stdout and stderr as before. The fix preserves the original behavior: it writes captured output to the log file and returns the same combined output to the caller, maintaining the sink's contract. No shell is invoked, so injection is eliminated.

## Behaviour changes

- Removed os.system() call; replaced with subprocess.run()
- Changed from shell command string to argument list passed to subprocess
- Explicit capture of stdout and stderr via capture_output=True (returns CompletedProcess object)
- Output written to log file as before; file read and returned unchanged
- Exit status of ping command is now available in result.returncode (was discarded before, still not used by caller)
- Error handling: subprocess.run() does not raise an exception for non-zero exit status by default (same as os.system()), so behavior is preserved

