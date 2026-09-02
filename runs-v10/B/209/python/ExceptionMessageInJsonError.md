## Verdict

Exploitable. The exception message `str(e)` on line 22 directly exposes internal error details to the client. File I/O or JSON parsing exceptions can leak file paths, system configuration, or internal structure.

## Source

Any exception raised during receipt file access or JSON parsing (lines 17–18):
- `FileNotFoundError` with file path
- `json.JSONDecodeError` with parsing details
- `PermissionError`, `IOError`, or other OS-level errors

## Fix

**Vulnerable code:**
```python
except Exception as e:
    # SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
    return jsonify({"error": str(e)}), 500
```

**Fixed code:**
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
        logger.error("Failed to load receipt", exc_info=True)
        return jsonify({"error": "An error occurred"}), 500
```

## Explanation

The fix replaces the exception message with a generic client-facing error message while logging the full exception details server-side. The `exc_info=True` parameter ensures the complete stack trace is captured in the logs for debugging and monitoring, while the client receives only "An error occurred" without exposure to internal paths, library names, or system configuration. The HTTP 500 status code is preserved, maintaining the existing error semantics.

## Behaviour changes

- Error response message changed from the actual exception text to a generic string. This prevents information leakage but removes implementation details from the client response.
- Full exception traceback now logged server-side via `logger.error(..., exc_info=True)`. This enables backend monitoring and debugging without exposing details to users.
- Requires adding `import logging` and configuring a logger. The logging output is internal and does not affect the HTTP response contract.
