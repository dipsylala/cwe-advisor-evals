## Verdict
Exploitable

## Source
`filename = request.args.get("filename")` (line 12) — untrusted user input from HTTP query parameters

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
    
    # Use Flask's send_from_directory which safely validates the path is within REPORTS_DIR
    # and returns 404 if traversal is attempted
    return send_from_directory(REPORTS_DIR, filename)


if __name__ == "__main__":
    app.run()
```

## Explanation
The original code passed untrusted user input from `request.args.get("filename")` directly into `os.path.join()` and then to `open()` without any path validation. An attacker could use sequences like `../../../etc/passwd` or `/etc/passwd` to read files outside the intended `REPORTS_DIR`, because `os.path.join()` has no containment enforcement. The fix uses Flask's `send_from_directory()`, which applies `werkzeug.utils.safe_join()` internally to resolve the joined path and verify it stays within the base directory; it returns a 404 response if any traversal attempt is detected. This eliminates the vulnerability while also simplifying the code to use the framework's intended file-serving pattern. `send_from_directory()` automatically handles content-type headers and proper HTTP response generation for file downloads.

## Behaviour changes
- The return value shifts from manually reading the file and constructing a tuple `(contents, 200, {"Content-Type": "application/pdf"})` to returning Flask's `Response` object from `send_from_directory()`.
- Content-Type headers are now automatically set by `send_from_directory()` based on the file extension, rather than being hard-coded to `application/pdf`.
- Files outside `REPORTS_DIR` now return HTTP 404 instead of raising an exception, which is the standard HTTP semantics for a file serving endpoint.
- The import of `send_from_directory` from Flask replaces the manual `open()` call.

All these changes align with Flask's intended file-serving pattern and are transparent to legitimate clients — the endpoint continues to serve files within the permitted directory with correct MIME types.
