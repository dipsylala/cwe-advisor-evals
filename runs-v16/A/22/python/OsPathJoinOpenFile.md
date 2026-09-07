## Verdict
Path traversal vulnerability confirmed. User-supplied filename is joined with a base directory but is never validated to ensure it stays within that directory. An attacker can escape REPORTS_DIR using path traversal sequences like `../` or absolute paths.

## Source
Line 12-13 receives the filename directly from the request and constructs a path without validation:
```python
filename = request.args.get("filename")
report_path = os.path.join(REPORTS_DIR, filename)
```

The vulnerability reaches the sink at line 16 where the unvalidated path is opened.

## Fix
Resolve the path to its canonical form and verify it remains within the base directory before opening:

```python
import os
from pathlib import Path

@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    # Resolve the base directory and the requested path to absolute canonical forms
    base_dir = os.path.realpath(REPORTS_DIR)
    report_path = os.path.realpath(os.path.join(REPORTS_DIR, filename))
    
    # Verify the resolved path is within the base directory
    if not report_path.startswith(base_dir + os.sep) and report_path != base_dir:
        return "Forbidden", 403
    
    with open(report_path, "rb") as report_file:
        contents = report_file.read()
    
    return contents, 200, {"Content-Type": "application/pdf"}
```

Alternatively, using `pathlib` for cleaner code:

```python
from pathlib import Path

@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    # Resolve paths to absolute canonical forms
    base_dir = Path(REPORTS_DIR).resolve()
    report_path = (Path(REPORTS_DIR) / filename).resolve()
    
    # Verify the resolved path is within the base directory
    try:
        report_path.relative_to(base_dir)
    except ValueError:
        return "Forbidden", 403
    
    with open(report_path, "rb") as report_file:
        contents = report_file.read()
    
    return contents, 200, {"Content-Type": "application/pdf"}
```

## Explanation
`os.path.join()` does not prevent path traversal. When a filename contains `../` sequences or starts with `/`, it can escape the intended base directory. Additionally, symlinks can redirect to files outside the base directory.

The fix resolves both paths to their canonical absolute forms using `realpath()` (or `Path.resolve()` with pathlib), which:
- Normalizes relative path sequences like `../`
- Expands symlinks to their actual targets
- Provides an absolute path that can be safely compared

By verifying the resolved path starts with the base directory (with proper separator checking to prevent prefix bypasses like `/srv/app/reports-evil`), we ensure the file access is confined to the intended directory. If validation fails, return HTTP 403 Forbidden.
