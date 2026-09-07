## Verdict
CWE-209 confirmed. The exception object is converted to a string and returned directly in the JSON response, exposing internal error details to the client.

## Source
Line 22 constructs the error response from `str(e)`, which includes the exception message. This message may contain sensitive information such as file paths (e.g., `/var/data/receipts/invalid_id.json`), database connection strings, or other implementation details.

## Fix
### File: ExceptionMessageInJsonError.py
```python
import json
import os
import logging

from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

RECEIPTS_DIR = "/var/data/receipts"


@app.route("/api/receipts")
def get_receipt():
    receipt_id = request.args.get("id")
    receipt_path = os.path.join(RECEIPTS_DIR, f"{receipt_id}.json")

    try:
        with open(receipt_path) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        logger.error("Error retrieving receipt", exc_info=True)
        return jsonify({"error": "Failed to retrieve receipt"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation
The fix removes the exception message from the client-facing response and instead:
1. Logs the full exception details with `logger.error(..., exc_info=True)` for debugging and monitoring purposes.
2. Returns a generic, non-revealing error message to the client: `"Failed to retrieve receipt"`.

This approach maintains observability for operators (who can access server logs) while preventing sensitive information disclosure to end users.
