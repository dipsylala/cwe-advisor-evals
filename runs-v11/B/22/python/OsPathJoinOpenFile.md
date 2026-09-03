## Verdict

exploitable

## Source

`request.args.get("filename")` receives untrusted user input from a URL query parameter (line 12).

## Fix

**Vulnerable code:**

```python
@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)

    # SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}
```

**Fixed code:**

```python
from pathlib import Path

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"
BASE_DIR = Path(REPORTS_DIR).resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    
    # Resolve the joined path and verify containment within BASE_DIR
    candidate = (BASE_DIR / filename).resolve(strict=False)
    
    if not candidate.is_relative_to(BASE_DIR):
        return "", 404
    
    if not candidate.is_file():
        return "", 404

    with open(candidate, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}
```

## Explanation

The fix resolves the joined path to its canonical form using `Path.resolve(strict=False)`, which eliminates relative path segments (`..`, `.`) and symlink indirection without requiring the file to exist. It then uses `is_relative_to()` to verify the resolved path remains within `BASE_DIR` - this path-component-aware check prevents attacks like `../documents-archive/file.txt` that would pass a string prefix test. The `is_file()` check ensures the target exists and is not a directory, and any path outside the allowed directory or that does not exist returns 404. The original `os.path.join()` is replaced with `Path` division, which uses the same semantics but integrates with the containment validation. The value passed to `open()` is now the validated canonical path, never the raw request input.

## Behaviour changes

1. **Added import**: `from pathlib import Path` - required for path canonicalization and containment checks.
2. **Added constant**: `BASE_DIR = Path(REPORTS_DIR).resolve()` - stores the canonical base directory once at module load time.
3. **Changed path construction**: From string-based `os.path.join()` to `Path` object division operator, which have identical joining semantics but integrate with validation.
4. **Added containment validation**: `is_relative_to()` check rejects paths outside `BASE_DIR`; returns 404 instead of proceeding to open.
5. **Added existence check**: `is_file()` rejects directories and nonexistent paths; returns 404.
6. **Path object passed to open()**: The sink receives a `Path` object instead of a string. Both work identically with `open()`, so the file reading behavior is unchanged.
7. **Error response changed**: Requests for files outside the directory or nonexistent files now return 404 (the endpoint's own choice) instead of raising `FileNotFoundError`. This is a security improvement for a web endpoint - no exception details leak to the client.
