## Verdict

Exploitable

## Source

User-supplied `filename` parameter from `request.args.get("filename")` at line 12, used directly in path construction without validation.

## Fix

**Vulnerable code:**
```python
@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)

    # SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}
```

**Fixed code:**
```python
from flask import send_from_directory

@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    return send_from_directory(REPORTS_DIR, filename)
```

## Explanation

The vulnerability occurs because `os.path.join()` does not prevent path traversal—a filename containing `../` sequences or absolute paths can escape the intended `REPORTS_DIR` and access arbitrary files. The attacker can request `?filename=../../../etc/passwd` and the resulting path resolves to `/etc/passwd` instead of remaining under `/srv/app/reports`. The fix replaces unsafe path handling with Flask's `send_from_directory()`, which internally applies `werkzeug.utils.safe_join()`. This function canonicalizes the joined path, verifies it stays within the base directory using path-component-aware comparison (not string prefix), and returns 404 if the file escapes the allowed directory or does not exist. This eliminates the path traversal vector while leveraging a battle-tested framework helper.

## Behaviour changes

- Response format changes from a tuple `(bytes, 200, dict)` to a Flask Response object. The file content and HTTP 200 status are preserved; only the wrapper type changes to enable proper Flask response handling.
- Content-Type header is now auto-detected from file extension instead of hardcoded as `"application/pdf"`. Files with other extensions (e.g., `.txt`, `.json`) will report their correct MIME type.
- Missing, invalid, or out-of-bounds filenames now return HTTP 404 instead of raising `FileNotFoundError`. This prevents error tracebacks from leaking information about the filesystem.
- Symlinks pointing outside `REPORTS_DIR` are rejected with 404, closing a secondary path traversal vector.
