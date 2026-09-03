## Verdict

Exploitable.

## Source

Exception `e` caught at line 20 from `open()` or `json.load()` calls. Exceptions from `FileNotFoundError`, `PermissionError`, `JSONDecodeError`, etc. carry sensitive details in their message string.

## Fix

Replace `str(e)` with a generic error message. Add server-side logging to capture the full exception details (path, stack trace) for debugging without exposing them to the client.

**Vulnerable code:**
```python
try:
    with open(receipt_path) as f:
        data = json.load(f)
    return jsonify(data)
except Exception as e:
    # SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
    return jsonify({"error": str(e)}), 500
```

**Fixed code:**
```python
import logging

logger = logging.getLogger(__name__)

# ... in the route handler:
try:
    with open(receipt_path) as f:
        data = json.load(f)
    return jsonify(data)
except Exception as e:
    logger.error("Failed to retrieve receipt", exc_info=True)
    return jsonify({"error": "Failed to retrieve receipt"}), 500
```

## Explanation

The original code exposes the exception message via `str(e)`, which reveals sensitive information: `FileNotFoundError` shows the attempted file path (leaking the server directory structure), `JSONDecodeError` shows line numbers and parse details. The fix replaces `str(e)` with a fixed, generic message that describes the user's situation ("Failed to retrieve receipt") without disclosing internal architecture. The full exception details (message, traceback, file paths) are logged server-side with `exc_info=True`, making them available for debugging and monitoring without exposing them to the client.

## Behaviour changes

Added import: `import logging` and logger initialization. The exception details are now logged server-side instead of returned to the client. The HTTP response body changes from the exception message to a static generic message. The status code remains 500 and the response format (JSON with "error" key) is preserved.
