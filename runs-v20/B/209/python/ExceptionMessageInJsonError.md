## Verdict

exploitable

- cwe_id: CWE-209
- location: ExceptionMessageInJsonError.py, line 22
- confidence: high

## Source

The exception `e` raised inside the `try` block at lines 16-19 (`open(receipt_path)` or `json.load(f)`). `receipt_path` is built from `receipt_id = request.args.get("id")`, an attacker-controlled query parameter, so the raised exception's message routinely embeds attacker-influenced and server-internal data: a `FileNotFoundError`/`OSError` from `open()` includes the full absolute path (`/var/data/receipts/<id>.json`), and a `JSONDecodeError` from `json.load()` includes line/column position and a snippet of the file's on-disk content.

## Fix

### File: ExceptionMessageInJsonError.py

```python
import json
import logging
import os

from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

RECEIPTS_DIR = "/var/data/receipts"


@app.route("/api/receipts")
def get_receipt():
    receipt_id = request.args.get("id")
    receipt_path = os.path.join(RECEIPTS_DIR, f"{receipt_id}.json")

    try:
        with open(receipt_path) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception:
        logger.error("Failed to load receipt %s", receipt_id, exc_info=True)
        return jsonify({"error": "Request failed"}), 500


if __name__ == "__main__":
    app.run()
```

- library_recommendation: none - the fix uses only the standard library `logging` module, already reachable from Flask's own logger setup.

## Explanation

The sink at line 22 built the client-visible JSON body directly from `str(e)`, so any exception raised while opening or parsing the receipt file - including the absolute filesystem path and, for a malformed file, a snippet of its raw content - was returned verbatim to the caller with a 500 status. The fix keeps the same response shape and status code but replaces the message with a fixed, generic string (`"Request failed"`), matching the guidance's contract that user-facing error bodies come from a server-controlled constant, not from exception text. The full exception detail is preserved for operators via `logger.error(..., exc_info=True)`, which logs the formatted traceback server-side (the `receipt_id` is logged as a separate `%s` argument rather than concatenated into the message, keeping the log record structured). The `except Exception as e` binding was narrowed to `except Exception` since the fixed code no longer reads `e` directly - the traceback is captured by `exc_info=True` from the active exception context instead.

## Behaviour changes

- Response body on error changes from `{"error": "<raw exception text>"}` to `{"error": "Request failed"}` - this is the intended fix; the raw exception text was the leaked sensitive information.
- A new server-side log entry is written on every failure via `logger.error(...)`, using Python's root/App logger (Flask's `app.logger` is not required here since the `logging` module's root handlers apply by default) - this is additive, required to preserve operator visibility into the underlying error, and matches the guidance's "log detailed errors server-side" principle.
- HTTP status code (500) and response format (`jsonify(...)`, a JSON object with an `error` key) are unchanged.
- No change to the success path (line 19) or to `receipt_path` construction; the path-traversal exposure via unvalidated `receipt_id` in `os.path.join` is a separate, pre-existing condition (CWE-22) outside this CWE-209 finding and was left untouched.
- verification: `python -m py_compile` run against the fixed file in a scratch copy (not the shared fixture) - compiled with no errors or warnings.
- assumptions: none - the taint sink (`str(e)` in a JSON response) and remediation pattern (generic message + `exc_info=True` logging) are both named explicitly in `cwe/209/python/INDEX.md`.
