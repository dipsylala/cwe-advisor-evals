## Verdict
**Confirmed CWE-22 Path Traversal vulnerability.** The code constructs a file path by joining a user-controlled filename with a base directory without validating that the resulting path stays within the intended directory. An attacker can use relative path sequences like `../` to traverse to arbitrary locations on the filesystem.

## Source
```python
@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)
    
    # Vulnerable: opens any file reachable via path traversal
    with open(report_path, "rb") as report_file:
        contents = report_file.read()
```

The attacker can request `/reports/download?filename=../../../etc/passwd` and read arbitrary files outside `REPORTS_DIR`.

## Fix
```python
import os
from pathlib import Path
from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = Path("/srv/app/reports").resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    if not filename:
        return "filename required", 400
    
    # Reject path traversal attempts
    if ".." in filename or filename.startswith("/"):
        return "invalid filename", 400
    
    # Resolve to absolute path and verify it's within allowed directory
    report_path = (REPORTS_DIR / filename).resolve()
    if not str(report_path).startswith(str(REPORTS_DIR)):
        return "path traversal detected", 403
    
    # Verify file exists before attempting to open
    if not report_path.is_file():
        return "file not found", 404
    
    try:
        contents = report_path.read_bytes()
    except (IOError, OSError):
        return "error reading file", 500
    
    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation
The fix enforces path boundary validation before opening the file:

1. **Reject traversal patterns**: Check that the filename does not contain `..` (relative traversal) or start with `/` (absolute paths). This catches obvious attack vectors.

2. **Normalize and verify scope**: Use `Path.resolve()` to resolve both the base directory and the requested file to absolute canonical paths, eliminating symlink ambiguity. Then verify the result's string representation starts with the allowed directory's path. This ensures even edge cases like double-encoded sequences cannot escape the boundary.

3. **File existence check**: Confirm the file is a regular file (`is_file()`) before attempting to open it, preventing directory traversal attempts or other file-type confusion.

4. **Error handling**: Separate error codes (400 for invalid input, 403 for access denied, 404 for not found, 500 for I/O errors) allow proper HTTP semantics while avoiding information disclosure.

The `Path.resolve()` normalization is the critical defence — it eliminates any remaining traversal patterns and symlink-based bypasses, ensuring the opened file is always under the intended directory.
