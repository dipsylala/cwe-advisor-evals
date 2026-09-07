## Verdict
CONFIRMED - Path traversal vulnerability at line 23. `os.path.join()` discards BASE_DIR when filename is absolute, allowing access to arbitrary files.

## Source
```python
document_path = os.path.join(BASE_DIR, filename)
```

Untrusted filename from request.args.get("file") is directly joined with BASE_DIR. If filename is an absolute path (e.g. `/etc/passwd`), os.path.join discards BASE_DIR and returns the absolute path unvalidated.

## Fix

### File: document_download.py

```python
"""Document download endpoint for the internal reports portal."""

import os

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

    # Resolve both paths to their canonical form to eliminate symlinks and .. traversals
    base_path = Path(BASE_DIR).resolve()
    requested_path = (Path(BASE_DIR) / filename).resolve()

    # Ensure the requested path is within BASE_DIR
    try:
        requested_path.relative_to(base_path)
    except ValueError:
        # Path is outside BASE_DIR or attempts traversal
        abort(403, description="Access denied")

    document_path = str(requested_path)

    if not os.path.isfile(document_path):
        abort(404, description="Document not found")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation
The fix uses `pathlib.Path.resolve()` to canonicalize both paths, eliminating symlinks and normalizing `..` sequences. It then uses `Path.relative_to()` to verify that the requested file path is within BASE_DIR. If the requested path is absolute or contains traversal that escapes the base directory, `relative_to()` raises ValueError, triggering a 403 response. This prevents both absolute path injection and `..` traversal attacks while allowing legitimate filename requests.
