## Verdict

The finding is exploitable. An attacker can supply a path traversal payload in the `filename` query parameter to read arbitrary files the application process can access, such as `../../../etc/passwd` or an absolute path like `/etc/passwd`.

## Source

The vulnerability originates at line 12 of `OsPathJoinOpenFile.py`: `filename = request.args.get("filename")` receives untrusted user input from the HTTP query string.

## Fix

The fixed code validates and canonicalizes the constructed path before opening it, ensuring it remains within the intended directory.

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
    report_path = os.path.join(REPORTS_DIR, filename)

    try:
        # Resolve the path to its absolute canonical form, verifying it exists
        resolved_path = Path(report_path).resolve(strict=True)
        base_dir = Path(REPORTS_DIR).resolve()

        # Verify the resolved path stays within the base directory using path component comparison
        if not resolved_path.is_relative_to(base_dir):
            return {"error": "Access denied"}, 403

        with open(resolved_path, "rb") as report_file:
            contents = report_file.read()
    except FileNotFoundError:
        return {"error": "File not found"}, 404

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix resolves the constructed path to its canonical absolute form using `Path.resolve(strict=True)`, which:
- Converts relative paths and symbolic links to their true absolute targets
- Raises `FileNotFoundError` if the file does not exist (appropriate for read operations)
- Prevents `os.path.join()` discarding the base when a second argument is absolute (the resolved form makes this moot)

After resolving both the constructed path and the base directory independently, the fix verifies containment using `is_relative_to()`, which performs path-component-aware comparison (unlike string prefix matching, which could incorrectly accept `/srv/app/documents-archive` as inside `/srv/app/documents`).

The resolved path is then passed to `open()`, ensuring the sink operates on the validated, canonical path. The tainted input (`filename`) is never passed downstream of the containment check.

## Behaviour changes

- **Error handling**: The fixed code returns HTTP 403 if a path traversal attempt reaches outside the base directory, and HTTP 404 if the file does not exist. The original would raise an unhandled exception. This is a deliberate improvement for a web endpoint.
- **Symlink handling**: Symbolic links are now resolved to their targets and validated. A symlink pointing outside the base directory is rejected.
- **Absolute path handling**: Absolute paths supplied in `filename` are now rejected, preventing direct attacks like `/etc/passwd`.
