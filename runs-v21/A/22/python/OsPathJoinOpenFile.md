## Verdict
Confirmed CWE-22 path traversal vulnerability. An attacker can supply a `filename` parameter containing directory traversal sequences (e.g., `../../../etc/passwd`) that bypass the intended `REPORTS_DIR` restriction. The fix validates that the resolved file path remains within the allowed directory before opening it.

## Source
```python
import os

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)

    # SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Fix
### File: OsPathJoinOpenFile.py
```python
import os

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)
    
    # Validate that the resolved path is within REPORTS_DIR
    real_reports_dir = os.path.realpath(REPORTS_DIR)
    real_report_path = os.path.realpath(report_path)
    
    if not real_report_path.startswith(real_reports_dir + os.sep):
        return "Access denied", 403

    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation
The vulnerability arises because `filename` flows directly from user input (`request.args.get`) into the file path construction. Although `os.path.join(REPORTS_DIR, filename)` concatenates paths, it does not prevent directory traversal sequences like `../` from escaping the base directory. For example, a request with `?filename=../../../etc/passwd` produces `/srv/app/reports/../../../etc/passwd`, which resolves to `/etc/passwd`.

The fix uses `os.path.realpath()` to resolve both the base directory and the constructed path to their canonical absolute forms, then validates that the resolved file path begins with the base directory path (including a separator). This ensures:

1. Symlinks are resolved to their true locations, preventing traversal through linked directories
2. Relative path components (`..`) are resolved and normalized
3. Any path escape attempts are detected and rejected with a 403 response

This containment check occurs before file access, making it a primary defense against path traversal.
