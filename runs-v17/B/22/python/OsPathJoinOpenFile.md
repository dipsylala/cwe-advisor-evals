## Verdict

Exploitable. User-supplied `filename` parameter flows directly into `os.path.join()` and then to `open()` with no validation. An attacker can use `../` sequences to escape the `REPORTS_DIR` base directory and read arbitrary files (e.g., `filename="../../../etc/passwd"`).

## Source

Line 12: `filename = request.args.get("filename")`

This is attacker-controlled input from the Flask query parameter with no constraint or validation before use.

## Fix

### File: OsPathJoinOpenFile.py

```python
import os

from flask import Flask, request
from pathlib import Path

app = Flask(__name__)

REPORTS_DIR = Path("/srv/app/reports").resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    candidate = (REPORTS_DIR / filename).resolve()
    
    # Verify the resolved path stays within REPORTS_DIR
    if not candidate.is_relative_to(REPORTS_DIR):
        return "Forbidden", 403
    
    # Verify the path exists and is a regular file
    if not candidate.is_file():
        return "Not found", 404
    
    with open(candidate, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix resolves both the base directory and the user-supplied path to absolute canonical form using `Path.resolve()`, which collapses `..` sequences and symlinks to their true destinations. It then checks containment with `Path.is_relative_to(REPORTS_DIR)`, which performs path-component-aware comparison (unlike string prefix matching, which would incorrectly pass `/srv/app/reports-secret`). The `is_file()` check confirms the path exists and is a regular file before opening. Together, these checks ensure the attacker-controlled `filename` cannot escape the reports directory or access non-files.

## Behaviour changes

- **Error handling changed**: The original code raises `FileNotFoundError` (or other exceptions) if the file does not exist or cannot be opened. The fixed code returns HTTP 403 if the path escapes the base directory, or HTTP 404 if the file does not exist or is not a regular file. This is a web-appropriate error response pattern instead of server 500 errors from unhandled exceptions.
- **Type change for REPORTS_DIR**: Changed from string to `Path` object. The change is internal to this function and improves path safety by using the pathlib API, with no external impact.
- **Added import**: `from pathlib import Path`. This is a standard-library import (Python 3.4+) with no external dependency.
- **Requirement**: Requires Python 3.9+ for the `is_relative_to()` method (available since Python 3.9; use `Path(candidate).relative_to(REPORTS_DIR)` and catch `ValueError` on 3.8 if needed, but 3.9+ is recommended).

