## Verdict

**Confirmed.** Line 22 returns the exception message directly to the client in a JSON response, exposing internal error details (file paths, system errors, library details).

## Source

Exception object `e` caught at line 20 from file I/O or JSON parsing operations. The exception's string representation is included in the response without sanitization.

## Fix

Replace `str(e)` with a generic error message. Add server-side logging to capture full exception details:

```python
import json
import os
import logging

from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)
app = Flask(__name__)

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
        return jsonify({"error": "An error occurred"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix replaces the exception message with a generic, client-safe message. The key changes:

1. **Generic error message**: `"An error occurred"` tells the user something failed without exposing internal details like file paths (`/var/data/receipts/...`), JSON parsing failures, or system configuration.

2. **Server-side logging**: `logger.error(..., exc_info=True)` captures the full exception traceback server-side where only administrators can access it. This preserves debugging information for developers while keeping the client response opaque.

3. **Separation of concerns**: User-facing responses now contain only information about the user's request result (success/generic failure), while internal diagnostic information stays in the server log.

## Behaviour changes

- **Client response**: Changes from `{"error": "FileNotFoundError: [Errno 2] No such file or directory: '/var/data/receipts/123.json'"}` (exposes path and system details) to `{"error": "An error occurred"}` (generic, safe).
- **Server logs**: Now includes full exception traceback via `exc_info=True`, enabling debugging and monitoring.
- **HTTP status**: Remains 500 (no change).
- **User experience**: Error message is less specific, but application no longer leaks internal architecture to clients.
