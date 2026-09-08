## Verdict
Confirmed. `os.path.join()` silently discards its first argument when the second is an absolute path, enabling directory restriction bypass.

## Source
Line 23: `document_path = os.path.join(BASE_DIR, filename)`

The `filename` parameter comes from untrusted user input via `request.args.get("file")` (line 18) with no path validation. An attacker can supply an absolute path like `/etc/passwd` to escape BASE_DIR entirely.

## Fix

### File: document_download.py

```python
"""Document download endpoint for the internal reports portal."""

import os

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

    # Reject absolute paths that would bypass BASE_DIR
    if os.path.isabs(filename):
        abort(400, description="Invalid file path")

    # Resolve the full path and normalize to handle .. traversal
    document_path = os.path.normpath(os.path.join(BASE_DIR, filename))
    base_dir_norm = os.path.normpath(BASE_DIR)

    # Ensure the resolved path stays within BASE_DIR
    if not document_path.startswith(base_dir_norm + os.sep):
        abort(400, description="Invalid file path")

    if not os.path.isfile(document_path):
        abort(404, description="Document not found")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation
The fix adds two validation layers:

1. **Absolute path check** (`os.path.isabs(filename)`): Rejects inputs starting with `/` or drive letters, preventing the `os.path.join()` bypass where `/etc/passwd` would discard `/srv/reports/documents`.

2. **Post-join containment check**: After normalization (which collapses `..` sequences), verifies the resolved path starts with `BASE_DIR/`. This catches both absolute paths and relative traversal attempts like `../../etc/passwd`.

The normalization step resolves `../` and other path components before checking containment, ensuring traversal attempts are caught. Requests for valid files under BASE_DIR pass through unchanged.
