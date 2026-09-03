## Verdict
Real vulnerability confirmed. Exception details are exposed to the client in the JSON response.

## Source
Line 22 converts the exception object to a string and includes it directly in the JSON response:
```python
return jsonify({"error": str(e)}), 500
```

The exception `e` from line 20 captures the full exception chain, which typically contains:
- File paths (e.g., `/var/data/receipts/user_id_123.json`)
- Internal directory structures
- Filesystem state and permission errors
- Library versions and stack traces

These details leak implementation information to unauthenticated clients.

## Fix
Replace the exception string with a generic, user-facing error message. Log the actual exception for debugging:

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
        logger.exception("Error retrieving receipt")
        return jsonify({"error": "Failed to retrieve receipt"}), 500
```

The logger preserves the full exception for server-side debugging, while the client receives only a generic message that reveals nothing about the application's internals.

## Explanation
CWE-209 occurs when error messages containing sensitive information are returned to untrusted users. Callers of this endpoint can:
- Infer the file structure by triggering exceptions with different input
- Learn that files are stored at `/var/data/receipts`
- Identify valid receipt IDs if the error message differs when a file is not found
- Extract stack traces or library versions if a deeper exception leaks

The fix follows defense-in-depth: a generic error message is sent to the client, while the actual exception is logged server-side for troubleshooting. This maintains debuggability without exposing implementation details.
