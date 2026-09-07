## Verdict

CWE-22 Path Traversal vulnerability confirmed. The code uses `os.path.join()` to construct a file path from untrusted user input without validating that the resolved path remains within `REPORTS_DIR`. An attacker can use absolute paths (`/etc/passwd`) or traversal sequences (`../../etc/passwd`) to access files outside the intended directory.

## Source

Line 12-16 of OsPathJoinOpenFile.py:

```python
filename = request.args.get("filename")
report_path = os.path.join(REPORTS_DIR, filename)

# SAST FINDING: CWE-22
with open(report_path, "rb") as report_file:
    contents = report_file.read()
```

The `filename` parameter is attacker-controlled and directly affects the path passed to `open()`. The `os.path.join()` call does not validate containment; it discards the base directory if the second argument is absolute, and does not resolve relative path components like `..`.

## Fix

### File: OsPathJoinOpenFile.py

```python
import os

from flask import Flask, request, send_from_directory

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    return send_from_directory(REPORTS_DIR, filename)


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix replaces the unsafe pattern of manually constructing and opening a path with Flask's `send_from_directory()`, which is the framework's built-in containment helper. Internally, `send_from_directory()` uses `werkzeug.utils.safe_join()` to:

1. Resolve the user-supplied filename against the base directory
2. Verify the resulting path stays within `REPORTS_DIR` by path-component-aware comparison
3. Return HTTP 404 if traversal is attempted

This approach eliminates the need to manually validate containment and ensures the final path cannot escape the intended directory. The guidance explicitly recommends using the framework's own containment helper over rebuilding the check manually, as it is less error-prone and the idiomatic Flask pattern for serving files.

## Behaviour changes

- **Response format improvement**: The endpoint now returns a proper Flask Response object (with appropriate headers and streaming) instead of raw bytes, which is the idiomatic Flask pattern
- **Security**: Path traversal attacks are now blocked by the framework; requests with `filename` values like `../../../etc/passwd` or `/etc/passwd` will return 404
- **Error handling**: Requests for non-existent files return 404 instead of raising an exception
