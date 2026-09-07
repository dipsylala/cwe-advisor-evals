## Verdict

Exploitable.

## Source

User-supplied filename from query parameter `request.args.get("file")` at line 18.

## Fix

### File: document_download.py

```python
"""Document download endpoint for the internal reports portal."""

from pathlib import Path

from flask import Blueprint, abort, request

BASE_DIR = "/srv/reports/documents"

documents_bp = Blueprint("documents", __name__)


@documents_bp.route("/documents/download")
def download_document():
    """Return the contents of a report stored under BASE_DIR.

    Example: GET /documents/download?file=q3-summary.pdf
    """
    filename = request.args.get("file")
    if not filename:
        abort(400, description="Missing 'file' query parameter")

    # Resolve the candidate path to absolute canonical form
    base_path = Path(BASE_DIR).resolve()
    candidate_path = (base_path / filename).resolve()

    # Verify containment within BASE_DIR
    if not candidate_path.is_relative_to(base_path):
        abort(403, description="Access denied")

    if not candidate_path.is_file():
        abort(404, description="Document not found")

    with open(candidate_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The original code used `os.path.join(BASE_DIR, filename)` which discards the BASE_DIR prefix when `filename` is an absolute path (e.g., `/etc/passwd`). This allows attackers to bypass the directory restriction. The fix uses `pathlib.Path` to resolve both the base directory and the candidate path to their canonical form, then verifies containment using `is_relative_to()`. This ensures that any absolute path or traversal sequence (`../`) that would escape the base directory is rejected with a 403 Forbidden response, while legitimate files within the directory tree are still accessible.

## Behaviour changes

- Removed `import os` (no longer used).
- Added `from pathlib import Path` for path canonicalization and containment verification.
- Changed file existence check from `os.path.isfile(document_path)` to `candidate_path.is_file()` (functionally equivalent).
- Added containment validation: paths that resolve outside BASE_DIR now trigger a 403 Forbidden response instead of potentially exposing files outside the intended directory. This is a security-critical change and not a regression.
