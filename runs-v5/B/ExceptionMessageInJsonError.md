## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location**: `ExceptionMessageInJsonError.py`, line 22

## Source

`request.args.get("id")` (the `id` query parameter) is joined into a filesystem path at line 14 and used to `open()` a file at line 17. Any `id` value that does not resolve to an existing, readable, valid-JSON file under `RECEIPTS_DIR` (a missing id, a permissions problem, a malformed stored file) raises an exception. The exception object itself is the sensitive value here: Python's built-in exception `str()` representations embed implementation detail — `FileNotFoundError`/`PermissionError` render as `[Errno N] <message>: '<path>'`, including the full absolute path (`/var/data/receipts/<id>.json`), and `json.JSONDecodeError` renders parser position detail about the file's contents. An attacker only has to request a nonexistent id to reach this branch on demand.

## Fix

```python
import json
import os

from flask import Flask, request, jsonify

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
        # VULNERABLE (was): return jsonify({"error": str(e)}), 500
        # str(e) on FileNotFoundError/PermissionError embeds the full
        # server-side path; json.JSONDecodeError embeds file-parsing detail.
        app.logger.error(
            "Failed to retrieve receipt id=%r: %s", receipt_id, e, exc_info=True
        )
        return jsonify({"error": "An error occurred while retrieving the receipt"}), 500


if __name__ == "__main__":
    app.run()
```

## Explanation

The handler's exception branch returned `str(e)` directly to the client as JSON, which for the exception types this code path actually raises (`FileNotFoundError`, `PermissionError`, `json.JSONDecodeError`) leaks the absolute server-side storage path and internal parsing state. The fix replaces the response body with a fixed, generic message ("An error occurred while retrieving the receipt") that describes the caller's situation without describing the application's internals, per the loaded CWE-209 guidance's core principle of separating user-facing messages from internal diagnostic detail. The full exception detail is preserved, not discarded — it is now written server-side via `app.logger.error(..., exc_info=True)`, which per the language guidance ensures the traceback goes to the log rather than the response, so debuggability is retained without exposing it to the client. The `500` status code is unchanged: this single `except Exception` branch already collapses several distinct failure modes into one generic response, so no new status-code distinction is introduced or removed by this fix; splitting that handling by exception type (e.g. surfacing a `404` for a missing receipt) is a separate, unrelated change and is out of scope for this CWE-209 fix.

## Behaviour changes

- **Response body changed**: `error` value is now a fixed string instead of the exception's message. This is the change that closes the weakness.
- **Server-side logging added**: `app.logger.error(...)` is a new call; the original code silently discarded the exception detail once the response was built. This surfaces (server-side only) exactly the detail the response no longer carries, so no diagnostic capability is lost.
- **Status code**: unchanged (`500`), and no exception type is caught, re-raised, or newly caught — only the body-construction line changes.
- **Response shape**: unchanged — still a JSON object with an `error` key at `500`, so existing clients parsing this contract are unaffected.

Assumption: `app.logger` (Flask's built-in per-app logger) is used rather than adding a `logging` import/module-level logger, since it is already available on the existing `app` object and requires no new dependency or configuration; this is a stylistic choice, not one the guidance requires either way.
