## Verdict

Real. The `filename` parameter from the HTTP GET request is passed directly to `os.path.join()` without validation and then used in `open()`. An attacker can provide a path traversal payload like `../../../etc/passwd` to read arbitrary files on the system.

## Source

Line 12: `filename = request.args.get("filename")` — untrusted HTTP GET parameter.

Line 13: `report_path = os.path.join(REPORTS_DIR, filename)` — joins without validation. Note that `os.path.join()` does not raise an error if the second segment begins with `..` or is absolute; it will discard the base directory.

Line 16: `with open(report_path, "rb") as report_file:` — taint sink opens the unvalidated path.

## Fix

Replace the manual path handling with Flask's built-in `send_from_directory()`, which internally uses `werkzeug.utils.safe_join()` to canonicalize and validate path containment:

```python
import os
from flask import Flask, request, send_from_directory

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run()
```

## Explanation

`flask.send_from_directory()` applies path validation via `werkzeug.utils.safe_join()`, which resolves the joined path and verifies it remains within the base directory (`REPORTS_DIR`) by path component, not string prefix. Attempts to traverse outside the directory (e.g., `../../../etc/passwd` or `/etc/passwd`) are rejected with a 404 response. The framework helper is preferred over rebuilding the containment check manually, both for correctness and consistency with Flask's design.

The `as_attachment=True` parameter sets the `Content-Disposition` header to prompt a download, preserving the intended behavior. Flask automatically adds appropriate headers like `Content-Length` and `Content-Type` based on the file extension.

## Behaviour changes

- **Response type**: Changed from manual tuple `(contents, 200, headers)` to a Flask `Response` object. The HTTP response is functionally equivalent but Flask sets additional headers automatically.
- **Error handling**: Invalid paths or non-existent files now return a standard 404 response instead of raising an unhandled exception. This is the correct behavior for a download endpoint.
- **Content-Disposition**: Added `Content-Disposition: attachment` header (via `as_attachment=True`) to prompt browser download rather than inline viewing.
