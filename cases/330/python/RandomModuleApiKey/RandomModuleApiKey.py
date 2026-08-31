"""Flask endpoint that issues an API key segment for a new integration."""
from flask import Flask, request, jsonify
import random

app = Flask(__name__)


@app.route("/api-key/generate")
def generate_api_key():
    prefix = "sk_live_"

    # Caller picks the numeric range for the key segment.
    min_val = int(request.args.get("min", "100000"))
    max_val = int(request.args.get("max", "999999"))

    # SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
    key_suffix = random.randint(min_val, max_val)

    api_key = f"{prefix}{key_suffix}"
    return jsonify({"api_key": api_key})


if __name__ == "__main__":
    app.run()
