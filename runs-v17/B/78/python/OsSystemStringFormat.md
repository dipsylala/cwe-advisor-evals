## Verdict

**CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Location**: OsSystemStringFormat.py, line 21

**Verdict**: exploitable

**Confidence**: high

The vulnerability is confirmed exploitable. The `target_host` parameter is obtained directly from untrusted user input via `request.get_json()` and passed to `os.system()` via string interpolation without validation or escaping. An attacker can inject arbitrary shell metacharacters to execute commands beyond the intended ping operation.

## Source

**Source**: Untrusted user input via `request.get_json()` → `payload.get("host", "").strip()` at line 14 assigned to `target_host`

**Sink**: `os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))` at line 21

**Data Flow**: The `target_host` variable flows directly from user input into the shell command string with no validation or escaping. The string interpolation operator `%` embeds the user-controlled value into a command string that is then executed by the operating system shell.

**Example Attack**: An attacker sending `{"host": "8.8.8.8; rm -rf /"}` would cause the command `ping -c 4 8.8.8.8; rm -rf / > /var/log/diagnostics/ping_last.log 2>&1` to execute, allowing arbitrary command execution.

## Fix

The fix replaces `os.system()` with `subprocess.run()` using an argument array with `shell=False`, and adds input validation as a secondary defense layer. This eliminates the shell interpretation of special characters in the user-supplied value.

### File: OsSystemStringFormat.py

```python
"""Network diagnostics endpoint for the internal admin dashboard."""

import os
import subprocess
import re
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

    # Validate hostname/IP: reject values starting with hyphen to prevent flag injection
    if not re.fullmatch(r"[a-zA-Z0-9:\.\-]+", target_host) or target_host.startswith("-"):
        return jsonify({"error": "invalid host format"}), 400

    log_path = "/var/log/diagnostics/ping_last.log"
    # Use subprocess with argument array and shell=False to prevent command injection
    with open(log_path, "w") as log_file:
        subprocess.run(
            ["ping", "-c", "4", target_host],
            stdout=log_file,
            stderr=subprocess.STDOUT
        )

    with open(log_path, "r") as log_file:
        output = log_file.read()

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
```

## Explanation

The fix eliminates the OS command injection by replacing `os.system()` with `subprocess.run()` using an argument array form and `shell=False`. By passing the host as a separate argument in a list rather than embedding it in a shell command string, the subprocess module does not interpret shell metacharacters. The `subprocess.run(["ping", "-c", "4", target_host], ...)` call ensures `target_host` is passed as a single argument to the `ping` program, preventing shell interpretation.

Additionally, the fix adds input validation using `re.fullmatch()` to ensure the hostname matches an allowlist pattern (alphanumeric, dots, hyphens, colons for IPv6 support) and rejects values starting with a hyphen. This secondary defense mitigates CWE-88 (Argument Injection) — while the argument array form prevents shell metacharacter injection, a value like `--to-command=malicious` could still be misinterpreted as an option flag by the target program. The validation ensures only valid hostname/IP characters are accepted and that the value cannot start with a dash that might be interpreted as an option.

The fix preserves the original behavior: writing ping output to a file, reading it back, and returning it to the user.

## Behaviour changes

**New imports**: `subprocess` (Python standard library), `re` (Python standard library) — both are part of Python's standard library and require no additional dependencies.

**Return value change**: `subprocess.run()` returns a `CompletedProcess` object, but the original code ignored the return value from `os.system()`, so this change has no behavioral impact. The return value is not used.

**Output capture**: Both the original (using `> %s 2>&1` shell redirection) and fixed (using `stdout=log_file, stderr=subprocess.STDOUT`) versions write ping output to the log file in the same way. The behavior is functionally identical.

**Error handling**: The fix does not add explicit error handling for `subprocess.run()` failures (e.g., `ping` command not found, timeout). In the original code, `os.system()` would return a non-zero exit code that was silently ignored. The fixed code similarly ignores the exit code. If robustness against command failures is desired, that is a separate enhancement beyond the scope of fixing the injection vulnerability.

**Input validation addition**: The regex validation is a new secondary defense that rejects invalid hostname formats. This is a breaking change only for inputs that do not represent valid hostnames (e.g., inputs with shell metacharacters, which were the attack vector). The validation correctly accepts all valid hostnames and IPv4/IPv6 addresses.

## Verification

**Syntax verification**: Python compilation check (`python -m py_compile`) passed without errors.

**Assumptions**:
- The Flask application is running on a Unix-like system where `ping -c` (count-based ping) is the correct command. On Windows, the command would be `ping -n`. The code assumes Unix/Linux based on the original `-c` flag usage.
- The subprocess module's `shell=False` parameter combined with argument array form correctly prevents command injection in Python. This is documented in Python's security considerations guide.
- The regex pattern `[a-zA-Z0-9:\.\-]+` is sufficient for valid hostnames and IP addresses (both IPv4 and IPv6 with colons). This covers standard DNS names and standard IP notation.
- File write permissions to `/var/log/diagnostics/ping_last.log` remain as they were in the original code.

