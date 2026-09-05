## Verdict
Confirmed. The exception handler returns the full exception message to the client, which can expose sensitive information such as file paths, internal system structure, or implementation details.

## Source
```python
try:
    with open(receipt_path) as f:
        data = json.load(f)
    return jsonify(data)
except Exception as e:
    return jsonify({"error": str(e)}), 500
```

Line 22 converts the caught exception to a string and sends it in the JSON response. Exceptions here can reveal file paths (e.g., `[Errno 2] No such file or directory: '/var/data/receipts/...'`) or other sensitive details.

## Fix
```python
import json
import logging
import os

from flask import Flask, request, jsonify

app = Flask(__name__)

RECEIPTS_DIR = "/var/data/receipts"
logger = logging.getLogger(__name__)


@app.route("/api/receipts")
def get_receipt():
    receipt_id = request.args.get("id")
    receipt_path = os.path.join(RECEIPTS_DIR, f"{receipt_id}.json")

    try:
        with open(receipt_path) as f:
            data = json.load(f)
        return jsonify(data)
    except (FileNotFoundError, json.JSONDecodeError):
        logger.exception("Error retrieving receipt %s", receipt_id)
        return jsonify({"error": "Receipt not found"}), 404
    except Exception as e:
        logger.exception("Unexpected error retrieving receipt %s", receipt_id)
        return jsonify({"error": "An error occurred"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation
The fix addresses CWE-209 by:

1. **Catching specific exceptions**: `FileNotFoundError` (file does not exist) and `json.JSONDecodeError` (invalid JSON) are caught separately to handle the most common cases.

2. **Returning generic error messages**: Client responses use safe, non-revealing messages ("Receipt not found", "An error occurred") instead of the full exception text. The HTTP status codes (404 for missing receipt, 500 for unexpected errors) convey sufficient information.

3. **Server-side logging**: The actual exception and request context are logged server-side via `logger.exception()`, preserving debugging information for administrators without exposing it to clients.

This prevents information disclosure while maintaining error visibility for operational troubleshooting.
