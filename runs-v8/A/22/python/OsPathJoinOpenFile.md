## Verdict
**Vulnerable.** The code accepts user-supplied input via `request.args.get("filename")` and uses it directly in `os.path.join()` without validating that the resolved path remains within the intended `REPORTS_DIR`. An attacker can provide path traversal sequences (e.g., `../../etc/passwd`) to read arbitrary files on the system.

## Source
```python
@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")  # Untrusted user input
    report_path = os.path.join(REPORTS_DIR, filename)
    
    with open(report_path, "rb") as report_file:  # Line 16: Sink
        contents = report_file.read()
    
    return contents, 200, {"Content-Type": "application/pdf"}
```

The data flow: `request.args.get()` → `os.path.join()` → `open()` (line 16, the sink).

## Fix
```python
import os

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)
    
    # Resolve to absolute paths and validate directory confinement
    real_report_path = os.path.realpath(report_path)
    real_base_dir = os.path.realpath(REPORTS_DIR)
    
    # Reject if resolved path escapes REPORTS_DIR
    if not real_report_path.startswith(real_base_dir + os.sep) and real_report_path != real_base_dir:
        return "Access denied", 403
    
    with open(real_report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation
The fix uses `os.path.realpath()` to resolve both the requested file path and the base directory to their canonical (absolute, symlink-resolved) forms. This neutralizes path traversal sequences like `..` and symlink-based escapes.

The check verifies that the resolved file path either is the base directory itself or starts with `base_dir + os.sep` (ensuring a directory boundary, not just a string prefix match). This prevents directory-escaping requests.

If the path would escape the intended directory, the handler returns a 403 Forbidden response instead of attempting to open the file. Only paths that resolve to within `REPORTS_DIR` proceed to `open()`.
