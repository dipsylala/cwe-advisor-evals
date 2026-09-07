## Verdict

The finding is confirmed. Line 22 returns the stringified exception directly to the client via `jsonify({"error": str(e)})`, exposing internal error details such as file paths, library messages, and system state that should remain server-side.

## Source

The source is any exception raised during file I/O (`open(receipt_path)`) or JSON parsing (`json.load(f)`). These operations can throw `FileNotFoundError`, `JSONDecodeError`, `IOError`, and other exceptions whose messages contain file paths and system details.

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
        logger.error("Failed to retrieve receipt", exc_info=True)
        return jsonify({"error": "Failed to retrieve receipt"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix separates internal and external error handling:

1. **Generic client message**: Replaced `str(e)` with the static string `"Failed to retrieve receipt"`. This prevents disclosure of file paths, exception types, library versions, and other internal details.

2. **Server-side logging**: Added `logger.error(..., exc_info=True)` before the response. The `exc_info=True` parameter ensures the full exception traceback is logged to the server's log file, preserving diagnostic information for debugging and monitoring while keeping it away from the client.

3. **Imports**: Added `logging` module to enable structured logging.

The HTTP 500 status code and JSON response format remain unchanged, preserving the API contract. The fix follows the guidance from cwe/209/python/INDEX.md: implement a custom exception handler that returns a generic message while capturing the full exception context via `logger.error(..., exc_info=True)`.

## Behaviour changes

**Before**: Any exception during receipt retrieval (file not found, malformed JSON, etc.) returns a response like `{"error": "[Errno 2] No such file or directory: '/var/data/receipts/123.json'"}` or `{"error": "Expecting value: line 1 column 1..."}`, exposing system paths and internal details to the client.

**After**: Any exception returns `{"error": "Failed to retrieve receipt"}`, while the full exception and traceback are written to the application's logger for server-side access. Attackers cannot enumerate file existence or infer system structure from error messages; developers retain full debugging information in logs.
