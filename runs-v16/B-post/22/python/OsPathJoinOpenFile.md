## Verdict

Exploitable. An attacker can supply a `filename` parameter containing path traversal sequences like `../` to escape the `/srv/app/reports` directory and read arbitrary files accessible to the application process.

## Source

**Input source:** `request.args.get("filename")` at line 12 - untrusted HTTP query parameter.

**Data flow:** The `filename` value is passed directly to `os.path.join(REPORTS_DIR, filename)` at line 13 without any validation. The joined path is then used in `open(report_path, "rb")` at line 16, which is the sink.

**Attack scenario:** Submitting `?filename=../../../etc/passwd` results in `os.path.join("/srv/app/reports", "../../../etc/passwd")` returning `/etc/passwd`, allowing the attacker to read files outside the intended directory.

## Fix

**Vulnerable code:**
```python
@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)

    # CWE-22: No containment validation; attacker can escape REPORTS_DIR
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}
```

**Fixed code (Flask-native approach - recommended):**
```python
from flask import send_from_directory

@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    # send_from_directory internally validates containment using werkzeug.safe_join
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)
```

**Alternative fixed code (using pathlib with manual containment check):**
```python
from pathlib import Path

@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    base_path = Path(REPORTS_DIR).resolve()
    
    # Resolve the joined path to absolute canonical form
    report_path = (base_path / filename).resolve()
    
    # Verify the resolved path remains within the base directory
    if not report_path.is_relative_to(base_path):
        return "Not found", 404
    
    # Verify it is a file (not directory or symlink to directory)
    if not report_path.is_file():
        return "Not found", 404
    
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}
```

## Explanation

The Flask-native fix using `send_from_directory()` is preferred because it leverages Flask and Werkzeug's battle-tested containment logic (`werkzeug.utils.safe_join()`), which properly handles edge cases like absolute paths and symlinks. This approach rejects `filename` values that escape the directory before any file operation occurs, raising an HTTP 404 instead.

The alternative pathlib approach demonstrates the underlying principle: resolve the joined path to its canonical absolute form using `Path.resolve()`, then verify it remains within the base directory using `is_relative_to()`. This must be done before opening the file. The key insight is that `os.path.join()` discards the base path if the second argument is absolute (e.g., `/etc/passwd`), so canonicalization must happen after the join and before the check.

Both approaches reject the value rather than attempting to strip traversal sequences, preventing log blindness and avoiding the non-recursive-replacement bypass (`....//` → `../`).

## Behaviour changes

**Flask-native approach:**
- **Return type change:** `send_from_directory()` returns a Flask response object instead of raw bytes. The HTTP status code and headers are handled automatically by Flask rather than explicitly in the tuple. This is semantically equivalent and actually improves header handling (e.g., proper `Content-Disposition`, `Content-Length`).
- **Error handling:** Files outside the directory now return HTTP 404 (via `werkzeug.NotFound` exception caught by Flask) instead of `FileNotFoundError`. This is correct security behavior—rejecting the request rather than exposing an error stack trace.
- **Directory behavior:** If `filename` resolves to a directory, `send_from_directory()` returns 404 (correct) rather than attempting to open it as a file (would raise `IsADirectoryError`).

**Pathlib approach:**
- **Explicit 404 responses:** Added explicit 404 returns on containment failure and missing file. These are additional control flow points but correctly reject invalid/escaping paths before filesystem operations.
- **Symlink handling:** `resolve()` follows symlinks by default, so a symlink pointing outside the directory is correctly rejected by the `is_relative_to()` check. This is correct behavior.
- **Return type:** Unchanged—still returns bytes and status tuple as in the original.

Both approaches preserve the core contract: returning file contents for legitimate paths and rejecting out-of-directory access. The security fix is transparent to valid callers within the allowed directory.

