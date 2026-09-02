## Verdict

Path traversal vulnerability confirmed. The `filename` parameter from user input is joined directly to the base directory without validation, allowing attackers to escape the intended directory using `../` sequences or absolute paths.

## Source

```python
filename = request.args.get("filename")
report_path = os.path.join(REPORTS_DIR, filename)

with open(report_path, "rb") as report_file:
    contents = report_file.read()
```

The vulnerability occurs because `os.path.join()` does not prevent path traversal when the user-supplied `filename` contains directory traversal sequences.

## Fix

```python
import os
from pathlib import Path

from flask import Flask, request, abort

app = Flask(__name__)

REPORTS_DIR = Path("/srv/app/reports").resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    if not filename:
        abort(400)
    
    requested_path = (REPORTS_DIR / filename).resolve()
    
    if not requested_path.is_relative_to(REPORTS_DIR):
        abort(403)
    
    try:
        with open(requested_path, "rb") as report_file:
            contents = report_file.read()
    except FileNotFoundError:
        abort(404)
    
    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix uses `pathlib.Path` to securely handle path operations:

1. **Resolve base directory**: `REPORTS_DIR = Path("/srv/app/reports").resolve()` converts the base path to an absolute, canonical form.

2. **Construct and resolve requested path**: `(REPORTS_DIR / filename).resolve()` constructs the full path and resolves it to its canonical form, eliminating any `../` or symbolic link tricks.

3. **Validate containment**: `is_relative_to(REPORTS_DIR)` ensures the resolved path is within or under the base directory. If a user supplies `../../../etc/passwd` or an absolute path like `/etc/passwd`, the resolved path will not be relative to REPORTS_DIR, and the request is rejected with a 403 Forbidden response.

4. **Handle missing files**: A `FileNotFoundError` results in a 404 response rather than exposing the filesystem.

5. **Reject empty filename**: An empty filename parameter results in a 400 Bad Request response.

This approach closes the path traversal vulnerability by preventing access to any file outside the intended directory.
