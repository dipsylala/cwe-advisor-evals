## Verdict

**Exploitable.** CWE-22 (Path Traversal). `verdict: exploitable`, `confidence: high`.

## Source

- **Source**: `request.args.get("filename")` (line 12) — fully attacker-controlled, unvalidated Flask query parameter.
- **Flow**: the raw value is joined with `os.path.join(REPORTS_DIR, filename)` (line 13) with no canonicalization or containment check, then passed straight to the sink.
- **Sink**: `open(report_path, "rb")` (line 16).

Two distinct bypasses reach the sink unmitigated:
1. Relative traversal — `filename=../../etc/passwd` walks `os.path.join` out of `REPORTS_DIR`.
2. Absolute-path override — `os.path.join()` discards its first argument entirely when the second is absolute, so `filename=/etc/passwd` makes `report_path` equal `/etc/passwd`, bypassing `REPORTS_DIR` completely.

No validation, allowlist, or canonicalization exists between source and sink, so both routes are live.

## Fix

**Vulnerable code:**

```python
import os

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)

    # SAST FINDING: CWE-22 reported here. Sink is the next statement.
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

**Fixed code:**

```python
from pathlib import Path

from flask import Flask, request, abort

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"
BASE_DIR = Path(REPORTS_DIR).resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = (BASE_DIR / filename).resolve(strict=True)

    if not report_path.is_relative_to(BASE_DIR) or not report_path.is_file():
        abort(404)

    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix replaces the untrusted `os.path.join()` + `open()` pair with a resolve-then-contain pattern. `BASE_DIR` is canonicalized once at module load with `Path.resolve()`. On each request, the untrusted `filename` is joined onto `BASE_DIR` and the *result* is resolved with `Path.resolve(strict=True)`, which follows symlinks and collapses any `..` segments into a real, absolute, canonical path (unlike `os.path.normpath()`/`os.path.abspath()`, which only manipulate the string). The code then checks `report_path.is_relative_to(BASE_DIR)` — a path-component-aware comparison, not a string prefix check — before opening anything, so both the relative-traversal route and the absolute-path-override route are caught: whichever real file the resolved path points to, it is only opened if it is still inside `REPORTS_DIR`. `is_file()` additionally rejects a resolved path that is a directory or other non-regular file. The value passed to `open()` is the same resolved, checked `report_path` variable — the code never re-derives the path from the raw request value after validation.

## Behaviour changes

- **Import swap**: `import os` removed (no longer used once `os.path.join` is replaced) and `pathlib.Path` / `flask.abort` added. No functional effect beyond supporting the fix.
- **Traversal/absolute-path requests now return 404 instead of leaking the file**: previously `filename=../../etc/passwd` or `filename=/etc/passwd` returned 200 with the target file's contents; now `is_relative_to()`/`is_file()` fails and the route returns 404. This is the security fix itself, not incidental — no information about *why* the request was rejected is disclosed (404 rather than 403, to avoid confirming a path's existence outside the root).
- **Missing-file failure mode is unchanged**: a `filename` that resolves to a real path under `REPORTS_DIR` which doesn't exist still raises `FileNotFoundError` (from `resolve(strict=True)` instead of from `open()`), producing the same uncaught-exception/500 behavior as the original code — this was not tightened, to keep the diff scoped to the traversal weakness.
- **Missing query parameter is unchanged**: `filename=None` still raises a `TypeError` before any file operation, the same as the original `os.path.join(REPORTS_DIR, None)` would.
- All other behavior — route path, response body (`contents`), status code on success, `Content-Type` header — is unchanged.
