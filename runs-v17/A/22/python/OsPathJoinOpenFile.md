## Verdict

**CONFIRMED**: Path traversal vulnerability via unsanitized user input in filename parameter.

## Source

The vulnerability exists in the `download_report()` function at line 16. The code accepts an untrusted filename from the HTTP request, concatenates it with a base directory using `os.path.join()`, and opens the resulting path without validating that the path remains within the intended directory.

```python
filename = request.args.get("filename")  # Untrusted user input
report_path = os.path.join(REPORTS_DIR, filename)  # Concatenation without validation
with open(report_path, "rb") as report_file:  # Sink: arbitrary file read
```

An attacker can craft a filename like `../../etc/passwd` to traverse up from `REPORTS_DIR` and read arbitrary system files.

## Fix

### File: OsPathJoinOpenFile.py

```python
import os

from pathlib import Path
from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    if not filename:
        return "Filename required", 400
    
    # Resolve base and requested paths to their canonical absolute forms
    base_path = Path(REPORTS_DIR).resolve()
    requested_path = (base_path / filename).resolve()
    
    # Verify the resolved path is within the base directory
    try:
        requested_path.relative_to(base_path)
    except ValueError:
        # Path traversal attempt detected
        return "Forbidden", 403
    
    # Ensure the requested path is a file and exists
    if not requested_path.is_file():
        return "Not found", 404
    
    with open(requested_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix uses `pathlib.Path.resolve()` to convert both the base directory and the user-supplied path to their canonical absolute forms. This operation:

1. **Eliminates traversal sequences**: `resolve()` expands `..` references and symlinks to their actual targets, collapsing any attempt to escape the base directory into its true canonical path.

2. **Validates containment**: After resolving both paths, `requested_path.relative_to(base_path)` verifies that the requested path is actually within the base directory. If the resolved path lies outside, `relative_to()` raises a `ValueError`, which is caught and returns a 403 Forbidden response.

3. **Adds boundary checks**: The code checks that the requested path is a file (not a directory) and exists before opening, preventing directory traversal and information disclosure about directory contents.

4. **Handles edge cases**: Returns 400 if no filename is provided, 404 if the file does not exist, and 403 if path traversal is detected.

This approach is more robust than string-based checks because it operates at the filesystem level, where the OS resolves symlinks and path normalization, making it impossible to bypass with encoded traversal sequences or other tricks.
