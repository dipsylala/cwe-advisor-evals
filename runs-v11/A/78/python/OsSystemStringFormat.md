## Verdict
Confirmed OS Command Injection via user-controlled string interpolation into `os.system()`.

## Source
Line 21 uses `os.system()` with a shell command string containing user-supplied `target_host` directly interpolated via `%` formatting. An attacker can inject shell metacharacters (`;`, `|`, `&&`, backticks, etc.) to execute arbitrary commands.

Example attack:
```python
# Input: "example.com; rm -rf /"
# Executed command: ping -c 4 example.com; rm -rf / > /var/log/diagnostics/ping_last.log 2>&1
```

## Fix
Replace `os.system()` with `subprocess.run()` using an argument list:

```python
import subprocess

@app.route("/admin/diagnostics/ping", methods=["POST"])
def run_ping_diagnostic():
    """Run a connectivity check against a host supplied by the admin UI and
    return the captured output so support staff can see the raw result."""
    payload = request.get_json(silent=True) or {}
    target_host = payload.get("host", "").strip()

    if not target_host:
        return jsonify({"error": "host is required"}), 400

    log_path = "/var/log/diagnostics/ping_last.log"
    
    # Pass command and arguments as a list; subprocess does not invoke a shell,
    # preventing shell metacharacter interpretation.
    with open(log_path, "w") as log_file:
        subprocess.run(
            ["ping", "-c", "4", target_host],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            check=False
        )

    with open(log_path, "r") as log_file:
        output = log_file.read()

    return jsonify({"host": target_host, "output": output})
```

## Explanation
`os.system()` invokes the shell to parse and execute the command string, allowing shell metacharacters in user input to be interpreted as operators. By switching to `subprocess.run()` with an argument list (not a shell string), each element is passed directly to the program without shell parsing. The `ping` command and its options (`"-c"`, `"4"`) are separate list elements, and `target_host` is a literal argument value — the shell never sees it and cannot interpret special characters in it. The file redirection (`>`) and error redirection (`2>&1`) are handled by passing `stdout` and `stderr` parameters to the subprocess call, completely bypassing the shell.
