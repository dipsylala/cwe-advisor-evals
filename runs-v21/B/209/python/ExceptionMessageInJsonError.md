## Verdict

Exploitable. Line 22 directly includes `str(e)` in the JSON response, exposing the raw exception message to clients.

## Source

Uncaught exception from `json.load()` (line 18) or `open()` (line 17). An invalid file path, malformed JSON, or missing file produces an exception whose message may contain system paths, file names, or internal error details.

## Fix

### File: ExceptionMessageInJsonError.py

```python
import json
import os
import logging

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
    except Exception as e:
        logger.error("Failed to retrieve receipt", exc_info=True)
        return jsonify({"error": "An error occurred while processing your request"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix eliminates the leak by separating user-facing and internal error handling. Line 25 replaces `str(e)` with a generic error message that reveals nothing about the application's internals. Line 24 logs the full exception with `exc_info=True`, which captures the complete traceback to the configured logging handler for server-side analysis. The logging import and logger initialization support this separation. The generic message satisfies the HTTP 500 contract—clients receive an opaque error—while detailed diagnostics remain secure on the server.

## Behaviour changes

- **Added `import logging`**: standard library for structured error logging, required to support server-side exception capture.
- **Added `logger = logging.getLogger(__name__)`**: creates a logger instance scoped to the module, follows Flask conventions and enables application-wide logging configuration without hardcoding details in this function.
- **Added `logger.error(..., exc_info=True)`**: captures the full traceback server-side before returning to client. The `exc_info=True` parameter is the mechanism that closes the weakness—it moves sensitive details from the response to the log. Without this parameter, the detailed exception information would be lost entirely, which would reduce debuggability.
- **Replaced `str(e)` with generic message in response**: removes the sensitive exception string from the JSON response. This is the primary fix; any exception type or internal error detail stays on the server.

The return status code, response structure, and HTTP contract remain unchanged.
