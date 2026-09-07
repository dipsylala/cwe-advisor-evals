## Verdict

exploitable

## Source

User-supplied `filename` from `request.args.get("file")` at line 18.

## Fix

### File: document_download.py

```python
"""Document download endpoint for the internal reports portal."""

from pathlib import Path

from flask import Blueprint, abort, request

BASE_DIR = Path("/srv/reports/documents")

documents_bp = Blueprint("documents", __name__)


@documents_bp.route("/documents/download")
def download_document():
    """Return the contents of a report stored under BASE_DIR.

    Example: GET /documents/download?file=q3-summary.pdf
    """
    filename = request.args.get("file")
    if not filename:
        abort(400, description="Missing 'file' query parameter")

    try:
        # Resolve the joined path to absolute form and verify containment
        candidate = (BASE_DIR / filename).resolve()
        if not candidate.is_relative_to(BASE_DIR):
            abort(404, description="Document not found")
    except ValueError:
        abort(404, description="Document not found")

    if not candidate.is_file():
        abort(404, description="Document not found")

    with open(candidate, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The original code was vulnerable because `os.path.join(BASE_DIR, filename)` silently discards the base directory when `filename` is an absolute path (e.g., `/etc/passwd`). An attacker could bypass the intended directory restriction by passing absolute paths or sequences like `../../etc/passwd`. The fix resolves the constructed path to its canonical absolute form using `Path.resolve()`, then verifies it stays within the base directory using `is_relative_to()` before any file operation. This ensures that both absolute-path attacks and relative-path traversal attempts are rejected. The resolved path is stored in a variable and consistently used for the file check and open operation, preventing TOCTOU issues.

## Behaviour changes

- Replaced `os.path.join()` with `pathlib.Path` operations and the `/` operator, which has the same semantics for path joining but allows use of `resolve()` and `is_relative_to()` for containment checking
- Added containment verification using `is_relative_to()` after path canonicalization; requests with absolute paths or traversal sequences that resolve outside BASE_DIR now abort with 404
- Changed from `os.path.isfile()` to `Path.is_file()` for consistency with pathlib usage
- Introduced exception handling for `ValueError`, which can be raised by `is_relative_to()` in edge cases on some Python versions; these cases now abort with 404
- Variable name changed from `document_path` to `candidate` to reflect that the path is unvalidated until the containment check passes
- Added explicit comment clarifying the resolve and containment check sequence
- Removed unused `import os` since `os.path.join()` and `os.path.isfile()` are no longer used
