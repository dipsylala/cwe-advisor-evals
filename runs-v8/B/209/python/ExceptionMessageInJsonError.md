## Verdict

**Confirmed.** Exception details are returned directly to the client in the JSON response, exposing the server's file path and internal error information.

## Source

`receipt_id = request.args.get("id")` (line 13) flows into `os.path.join(RECEIPTS_DIR, f"{receipt_id}.json")` (line 14), then to `open(receipt_path)` (line 17). When the file operation fails, the exception message is captured.

## Fix

Replace the exception handler on line 20-22 with generic error messaging and server-side logging:

```python
import logging

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
        return jsonify({"error": "An error occurred while retrieving the receipt"}), 500
```

Key changes:
- Add logging at module level: `logger = logging.getLogger(__name__)`
- Replace `str(e)` with a generic message
- Use `logger.error(..., exc_info=True)` to capture the full traceback server-side for debugging

## Explanation

The fix separates user-facing and internal error handling. The generic message "An error occurred while retrieving the receipt" tells the client something went wrong without exposing implementation details. The full exception (including the file path, error type, and traceback) is logged server-side with `exc_info=True`, making it available for debugging and monitoring while keeping it out of the client response. This prevents information disclosure while preserving diagnostic capability for developers and operators.

## Behaviour changes

**Client-visible:** Error response changes from a detailed exception message (which could name the file path or system error) to a generic, safe message.

**Server-side:** Full exception details with traceback now appear in the application log instead of being discarded.

**HTTP contract:** Status code remains 500. Response structure remains `{"error": "<message>"}` but with a constant message.
