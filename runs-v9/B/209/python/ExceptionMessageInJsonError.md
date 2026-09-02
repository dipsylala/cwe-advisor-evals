## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location**: `ExceptionMessageInJsonError.py`, line 22, inside `get_receipt()`
- **Assumption**: no existing logging configuration is present in this single-file case, so the fix introduces a standard-library `logging` logger rather than matching an established project convention.

## Source

- **Source**: `request.args.get("id")` (line 13, Flask query parameter, attacker-controlled) flows into `receipt_path = os.path.join(RECEIPTS_DIR, f"{receipt_id}.json")` (line 14).
- **Data flow**: `receipt_path` is passed to `open(receipt_path)` and `json.load(f)` inside the `try` block (lines 17-18). Either call can raise (`FileNotFoundError`, `PermissionError`, `IsADirectoryError`, `json.JSONDecodeError`, etc.), all caught by the bare `except Exception as e` (line 20).
- **Sink**: line 22, `return jsonify({"error": str(e)}), 500`, serializes the raw exception message directly into the HTTP response body sent to the client.
- **Why exploitable**: Python's built-in `OSError`/`FileNotFoundError` string representation embeds the full failing path, e.g. `[Errno 2] No such file or directory: '/var/data/receipts/<id>.json'`. This discloses the server's absolute filesystem layout (`RECEIPTS_DIR`) and confirms file-existence, which an attacker can use for enumeration or to sharpen a path-traversal attempt against `receipt_id`. A malformed JSON file would similarly leak a `json.JSONDecodeError` message with byte offsets. Nothing between the source and the sink constrains or discards this text before it reaches the response.

## Fix

Vulnerable code (line 20-22):

```python
    except Exception as e:
        # SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
        return jsonify({"error": str(e)}), 500
```

Fixed code:

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
    except Exception as e:
        logger.error("Failed to load receipt %r", receipt_id, exc_info=True)
        return jsonify({"error": "Request failed"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation

The handler no longer serializes `str(e)` into the client-visible JSON body. Instead, the exception is logged server-side via `logger.error(..., exc_info=True)`, which captures the full exception message and traceback for diagnostics without exposing them over the network, and the client receives a fixed, generic `"Request failed"` message per the CWE-209 guidance's core principle of separating user-facing responses from internal diagnostic detail. The log call includes `receipt_id` (the request parameter) rather than the derived filesystem path, and `%r`/lazy `%`-formatting is used so the value is not eagerly interpolated into a f-string before Python's logging machinery handles it, consistent with the Python-specific guidance on how logging filters and formatting are separately controlled.

## Behaviour changes

- **Response body changed**: `{"error": "<raw exception text>"}` becomes `{"error": "Request failed"}`. This is the fix itself, not incidental — the raw exception text is exactly the leaked sensitive detail, and no downstream contract in this file depends on the previous message content.
- **New side effect added**: a `logger.error(...)` call with `exc_info=True` now runs on every exception, writing the previously-discarded diagnostic detail (message and traceback) to the server log instead of the HTTP response. This preserves debuggability that the fix would otherwise remove.
- **Preserved**: HTTP status code (500), response content type (JSON via `jsonify`), the `"error"` key name, and the overall control flow (single `try/except Exception`, no new exception types introduced or suppressed). No other argument, return value, or code path was altered.
