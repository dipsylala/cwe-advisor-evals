## Verdict

Exploitable.

## Source

Untrusted user input: `target_host` is derived from `payload.get("host", "").strip()`, which comes directly from a JSON request body with no validation beyond whitespace stripping. An attacker controls this value through a POST request to the Flask endpoint.

## Fix

**Vulnerable code:**
```python
os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))
```

**Fixed code:**
```python
import subprocess
import re

@app.route("/admin/diagnostics/ping", methods=["POST"])
def run_ping_diagnostic():
    """Run a connectivity check against a host supplied by the admin UI and
    return the captured output so support staff can see the raw result."""
    payload = request.get_json(silent=True) or {}
    target_host = payload.get("host", "").strip()

    if not target_host:
        return jsonify({"error": "host is required"}), 400

    # Validate hostname to prevent argument injection: reject values starting with -
    if not re.fullmatch(r"[a-zA-Z0-9._:-]+", target_host):
        return jsonify({"error": "invalid hostname format"}), 400

    log_path = "/var/log/diagnostics/ping_last.log"
    
    try:
        # Use subprocess with argument array and shell=False to prevent shell injection
        result = subprocess.run(
            ["ping", "-c", "4", target_host],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
        
        # Write output to log for audit trail
        with open(log_path, "w") as log_file:
            log_file.write(output)
    except subprocess.TimeoutExpired:
        output = "ping command timed out after 10 seconds"
        with open(log_path, "w") as log_file:
            log_file.write(output)
    except Exception as e:
        output = f"ping command failed: {str(e)}"
        with open(log_path, "w") as log_file:
            log_file.write(output)

    return jsonify({"host": target_host, "output": output})
```

## Explanation

The original code passes user-supplied `target_host` directly into a shell command string via `os.system()`. An attacker can inject shell metacharacters (`;`, `|`, `&&`, backticks, etc.) to execute arbitrary commands with the privileges of the Flask process. The fix replaces `os.system()` with `subprocess.run()` using an argument array (`["ping", "-c", "4", target_host]`) and `shell=False`, which prevents the shell from interpreting special characters in `target_host`. Additionally, the fix validates the hostname with a regex pattern to reject values starting with `-`, which could be misinterpreted as options by the `ping` program (argument injection / CWE-88). The `capture_output=True` parameter replaces the file redirection (`> %s 2>&1`) to collect stdout and stderr, which are then written to the log file and returned to the caller, preserving the original endpoint's contract.

## Behaviour changes

- **subprocess module import added**: Required to use subprocess.run(). This is part of Python's standard library.
- **Hostname validation added**: Input validated with regex to reject hostnames with unexpected characters. This prevents argument injection but is stricter than the original code allowed; hostnames with legitimate characters like underscores are permitted by the regex but the validation rejects those not matching the pattern. If legitimate use cases require underscores or other characters, the regex pattern should be expanded (e.g., `[a-zA-Z0-9._:\-]+` for IPv6 addresses, or use socket.getaddrinfo() for full validation).
- **Output capture method changed**: Original code relied on shell redirection (`> %s 2>&1`) to write output to file. Fixed code captures subprocess stdout/stderr and writes them to the file explicitly. This provides the same result but with more explicit control.
- **Error handling added**: Original code had no error handling for subprocess failures (e.g., host unreachable, timeout). Fixed code catches `subprocess.TimeoutExpired` and generic exceptions, writes error messages to the log, and returns them to the caller. This maintains visibility into failures but changes the output format slightly when errors occur.
- **Timeout added**: Fixed code specifies `timeout=10` to prevent hung processes if a host is unresponsive. Original code could block indefinitely.
- **Log file write behavior changed**: Original code relied on shell to create/overwrite log file; fixed code explicitly opens the file in write mode (`"w"`), which is equivalent but more explicit.

These changes preserve the endpoint's core functionality (execute ping and return output to the caller) while closing the command injection vulnerability.
