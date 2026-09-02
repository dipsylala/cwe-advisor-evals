"""Network diagnostics endpoint for the internal admin dashboard."""

import os
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
    # SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    os.system("ping -c 4 %s > %s 2>&1" % (target_host, log_path))

    with open(log_path, "r") as log_file:
        output = log_file.read()

    return jsonify({"host": target_host, "output": output})


if __name__ == "__main__":
    app.run(debug=True)
