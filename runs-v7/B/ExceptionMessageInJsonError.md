## Verdict

Exploitable. The exception message from line 22 exposes the full file path when a receipt file does not exist or cannot be parsed, leaking information about the application's internal directory structure and file locations.

## Source

`request.args.get("id")` on line 13 - the receipt ID parameter provided by the user. When passed through `os.path.join()` on line 14, it constructs a file path that is disclosed via the exception message if the operation fails.

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
        logger.error("Failed to retrieve receipt", exc_info=True)
        return jsonify({"error": "An error occurred"}), 500
```

## Explanation

The fix separates user-facing error messages from internal diagnostic details. The client receives only a generic error message that does not reveal system internals, while the full exception details (including the file path and traceback) are logged server-side with `exc_info=True`. This preserves the ability to debug the issue through server logs while eliminating the information leak to clients. The logging handler ensures that the sensitive exception message is captured for investigation without being exposed in the HTTP response.

## Behaviour changes

The client-facing error message changes from a detailed exception string (e.g., `[Errno 2] No such file or directory: '/var/data/receipts/invalid.json'`) to a generic `"An error occurred"` message. The detailed information is now available only in server logs, not in the API response. This is the intended behaviour change required to close the information leak.
