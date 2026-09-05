## Verdict

Confirmed path traversal vulnerability. The `filename` parameter is joined to `REPORTS_DIR` without validation, allowing traversal via `../` sequences (e.g., `../../etc/passwd`) or absolute paths (e.g., `/etc/passwd`). Both bypass the intended directory containment.

## Source

```python
filename = request.args.get("filename")  # Untrusted user input
report_path = os.path.join(REPORTS_DIR, filename)  # Joins without validation
with open(report_path, "rb") as report_file:  # Opens the potentially-escaped path
    contents = report_file.read()
```

The sink is the `open()` call on line 16. The data flow is: request parameter → `os.path.join()` → `open()`.

## Fix

Replace the vulnerable pattern with canonicalization and containment verification:

```python
import os
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = Path("/srv/app/reports")


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    # Resolve the joined path to absolute canonical form
    report_path = (REPORTS_DIR / filename).resolve()
    
    # Verify the resolved path is within REPORTS_DIR
    if not report_path.is_relative_to(REPORTS_DIR):
        return {"error": "Access denied"}, 403
    
    # Confirm the path points to an existing file
    if not report_path.is_file():
        return {"error": "File not found"}, 404
    
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix applies three mitigations in order:

1. **Canonicalization via `Path.resolve()`**: Resolves the joined path to its absolute canonical form, collapsing all `..` and `.` components and following symlinks to their targets. This ensures that any traversal attempt is normalized into an absolute path that actually points to where the attacker wants to go.

2. **Containment verification via `Path.is_relative_to()`**: Checks whether the resolved path is logically within the allowed `REPORTS_DIR`. The `is_relative_to()` method is path-component-aware, preventing false matches like `/srv/app/documents-archive` matching a base of `/srv/app/documents` (string prefix checks would fail here).

3. **Existence check via `is_file()`**: Confirms the path points to an actual file before opening it, preventing directory traversal to directories themselves and catching non-existent path references early with a 404 response rather than an exception.

The fix uses `pathlib.Path` instead of `os.path.join()` because the `/` operator is clearer and integrates with `resolve()` and `is_relative_to()` on the same object.

## Behaviour changes

**Rejected requests** (previously would traverse):
- `GET /reports/download?filename=../../etc/passwd` → 403 (containment check fails)
- `GET /reports/download?filename=/etc/passwd` → 403 (absolute path fails containment)
- `GET /reports/download?filename=notes.txt/../../../etc/passwd` → 403 (resolved path is outside base)

**Rejected requests** (previously would error differently):
- `GET /reports/download?filename=nonexistent.pdf` → 404 (explicit check instead of exception)

**Allowed requests** (legitimate access unchanged):
- `GET /reports/download?filename=report.pdf` → 200 with file contents
- `GET /reports/download?filename=subdir/report.pdf` → 200 with file contents (if file exists in subdirectory)
