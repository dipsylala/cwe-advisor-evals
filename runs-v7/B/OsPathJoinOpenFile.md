## Verdict

Path Traversal confirmed. Attacker-controlled `filename` from HTTP query parameters is joined to `REPORTS_DIR` and opened without validation, allowing traversal to arbitrary filesystem locations.

## Source

Line 12: `filename = request.args.get("filename")` receives untrusted user input from HTTP request query parameters.

## Fix

Replace the vulnerable path construction and open operation with canonicalization and containment validation:

```python
import os
from pathlib import Path
from flask import Flask, request, send_file, abort

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    if not filename:
        abort(400)
    
    # Resolve the joined path to absolute canonical form
    report_path = Path(REPORTS_DIR) / filename
    try:
        resolved_path = report_path.resolve(strict=True)
    except (FileNotFoundError, ValueError):
        abort(404)
    
    # Verify the resolved path is contained within REPORTS_DIR
    base_dir = Path(REPORTS_DIR).resolve()
    if not resolved_path.is_relative_to(base_dir):
        abort(404)
    
    # Now safe to use the validated path
    return send_file(resolved_path, as_attachment=True, mimetype="application/pdf")


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix applies three controls from the CWE-22 Python guidance:

1. **Canonicalize:** `Path.resolve(strict=True)` converts the joined path to an absolute canonical form, resolving symbolic links and relative path references like `..`. The `strict=True` parameter raises `FileNotFoundError` if the file does not exist, which is appropriate for a download operation.

2. **Containment Check:** `is_relative_to()` verifies the resolved path is inside the approved base directory by comparing path components, not string prefixes. This prevents containment bypasses like `/srv/app/documents-archive` matching a base of `/srv/app/documents`.

3. **Use the Validated Path:** The code passes the resolved `resolved_path` variable to the file operation (`send_file()`), ensuring the value that was checked is the value that is opened. This prevents a race condition where validation and use operate on different paths.

The fix also switches to `send_file()`, which is Flask's recommended pattern for serving files and automatically handles content-type and streaming concerns more safely than manual `open()` and return.

## Behaviour changes

- Non-existent files return 404 instead of raising an unhandled exception.
- Files outside `REPORTS_DIR` (including symlink targets outside the directory) return 404.
- Traversal attempts like `../../../etc/passwd` are rejected with 404.
- Relative paths within the directory (e.g., `subdirs/file.pdf`) continue to work.
- Content-type is automatically set to `application/pdf` with `send_file()`, replacing the manual header configuration.
- The response uses `as_attachment=True` to trigger a download prompt instead of inline display.
