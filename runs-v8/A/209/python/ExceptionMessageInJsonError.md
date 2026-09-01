## Verdict

CWE-209 confirmed. Line 22 returns the raw exception message to the client via `str(e)`, exposing sensitive information such as file paths, system configuration, or exception details that could aid an attacker.

## Source

The vulnerable code is:
```python
except Exception as e:
    return jsonify({"error": str(e)}), 500
```

The exception message is returned directly to the client without sanitization.

## Fix

Replace the exception handling to return a generic error message to the client while logging the actual exception for debugging:

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
        return jsonify({"error": "Unable to retrieve receipt"}), 500
```

## Explanation

The fix applies CWE-209 remediation by separating information intended for debugging from information exposed to users:

- **Generic client response**: Return `{"error": "Unable to retrieve receipt"}` instead of `str(e)`. This prevents exposure of file paths, system configuration, or exception details to potential attackers.
- **Server-side logging**: Use `logger.exception()` to capture the full exception context (including the traceback) for debugging. This preserves diagnostic capability while keeping sensitive details in server logs only.

This pattern prevents information disclosure while maintaining both security (no sensitive data in responses) and debuggability (full details in logs accessible only to operators).
