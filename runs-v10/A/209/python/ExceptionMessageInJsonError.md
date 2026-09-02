## Verdict
CWE-209 confirmed. The exception message is directly serialized and returned to the client.

## Source
Lines 20-22: The exception handler catches all exceptions and returns their string representation in the JSON response.

```python
except Exception as e:
    return jsonify({"error": str(e)}), 500
```

## Fix
```python
import json
import logging
import os

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
        logger.exception("Error retrieving receipt")
        return jsonify({"error": "Unable to retrieve receipt"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation
The original code returns the raw exception message to the client, which can expose sensitive information like file paths, database details, or system configuration. The fix:
1. Logs the full exception server-side for debugging and monitoring
2. Returns a generic, non-revealing error message to the client
3. Maintains the same HTTP status code (500)

This approach preserves debugging capability while protecting sensitive system details from disclosure.
