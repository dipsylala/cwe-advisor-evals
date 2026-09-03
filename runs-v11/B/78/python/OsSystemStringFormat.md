## Verdict
exploitable

## Source
`target_host` from JSON payload at line 14 (`payload.get("host", "").strip()`). The value is user-controlled and reaches the sink without validation.

## Fix

**Vulnerable code (line 21):**
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

    # Validate host format to prevent argument injection and ensure valid hostname/IP
    if not re.fullmatch(r'[a-zA-Z0-9._-]+', target_host):
        return jsonify({"error": "invalid host"}), 400

    log_path = "/var/log/diagnostics/ping_last.log"
    # Use subprocess with argument list and shell=False to eliminate OS command injection
    with open(log_path, "w") as log_file:
        subprocess.run(
            ["ping", "-c", "4", target_host],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True
        )

    with open(log_path, "r") as log_file:
        output = log_file.read()

    return jsonify({"host": target_host, "output": output})
```

## Explanation

The vulnerability occurs because `os.system()` invokes a shell to parse the command string, and `target_host` is directly interpolated into that string without escaping or validation. An attacker can inject shell metacharacters (`;`, `|`, `$()`, backticks) to execute arbitrary commands.

The fix replaces `os.system()` with `subprocess.run()` using an argument list and `shell=False`. This eliminates shell parsing entirely and prevents shell metacharacter injection. The arguments are passed directly to the `ping` executable without shell interpretation. Additionally, input validation using `re.fullmatch()` restricts the host to valid characters (alphanumeric, dots, underscores, hyphens), preventing argument injection attacks that might otherwise exploit the ping command's option parsing. Output redirection is moved from shell syntax to Python file handling.

## Behaviour changes

- **Subprocess invocation**: Changed from `os.system()` (shell-based) to `subprocess.run()` with `shell=False` (direct process execution). This eliminates the shell interpretation layer entirely.
- **Argument passing**: Changed from string interpolation to an argument list `["ping", "-c", "4", target_host]`. Arguments are passed directly to the executable without shell parsing.
- **Output redirection**: Changed from shell redirection `> %s 2>&1` to Python file handle passed to `stdout` parameter with `stderr=subprocess.STDOUT`. Functionally equivalent but no shell involved.
- **Input validation**: Added `re.fullmatch()` check to restrict hostnames to valid characters, preventing both shell injection and argument injection vectors.
- **Return value**: `subprocess.run()` returns a `CompletedProcess` object (return value is ignored in both original and fixed code), whereas `os.system()` returns an integer exit code. Since the original code did not use the return value, this change is transparent to behavior.
- **File resource management**: Changed from implicit file handling to explicit `with` statement for `stdout`, ensuring proper file closure.
