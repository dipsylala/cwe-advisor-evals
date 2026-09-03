## Verdict
The vulnerability is confirmed. User-supplied `filename` from query parameters is directly joined with `REPORTS_DIR` without validation, allowing path traversal attacks via absolute paths (which override the directory prefix in `os.path.join()`) or relative traversal sequences.

## Source
Line 12–13: The `filename` parameter is read directly from user input and joined with `REPORTS_DIR` without any path validation or canonicalization. Line 16 then opens the constructed path, allowing an attacker to read arbitrary files by supplying paths like `/etc/passwd` or `../../../../etc/passwd`.

## Fix
Validate that the resolved file path remains within the allowed directory before opening it:

```python
import os
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    # Validate: reject absolute paths and traversal sequences
    if not filename or filename.startswith('/') or '..' in filename:
        return "Invalid filename", 400
    
    # Construct and canonicalize the path
    report_path = os.path.normpath(os.path.join(REPORTS_DIR, filename))
    reports_dir_abs = os.path.normpath(REPORTS_DIR)
    
    # Verify the resolved path is within REPORTS_DIR
    try:
        Path(report_path).relative_to(reports_dir_abs)
    except ValueError:
        # Path is outside REPORTS_DIR
        return "Access denied", 403
    
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation
The fix uses three layers of defense:

1. **Input validation**: Reject any filename that is empty, starts with `/` (absolute path), or contains `..` (traversal sequence).

2. **Path canonicalization**: `os.path.normpath()` resolves `.` and `..` sequences and normalizes separators, ensuring consistent representation of the intended path.

3. **Confinement verification**: `Path.relative_to()` confirms the resolved path is a descendant of `REPORTS_DIR` by computing the relative path from the directory to the file. If the file is outside the directory, this raises `ValueError`, and the request is denied with a 403 response.

Together, these steps ensure that even if an attacker supplies a crafted filename with embedded traversal sequences or tricks the application logic, the canonicalized path cannot escape the intended directory boundary.
