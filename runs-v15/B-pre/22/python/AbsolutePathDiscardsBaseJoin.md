## Verdict
The finding is **confirmed**. `os.path.join(BASE_DIR, filename)` discards `BASE_DIR` when `filename` is an absolute path. An attacker can provide `filename="/etc/passwd"` and retrieve any readable file on the system.

## Source
User-supplied `filename` query parameter (line 18) is joined with `BASE_DIR` without validation that the result stays within the intended directory.

## Fix

```python
"""Document download endpoint for the internal reports portal."""

import os
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

    # Resolve the joined path to absolute canonical form, handling .. and symlinks
    document_path = (BASE_DIR / filename).resolve()

    # Verify the resolved path is within BASE_DIR using path-component-aware containment
    if not document_path.is_relative_to(BASE_DIR):
        abort(403, description="Access denied")

    if not document_path.is_file():
        abort(404, description="Document not found")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The vulnerability occurs because `os.path.join()` and `/` operator on path objects will discard the base directory when the second operand is an absolute path. For example, `os.path.join("/srv/reports", "/etc/passwd")` returns `"/etc/passwd"`, ignoring the base entirely.

The fix uses three key techniques from CWE-22 remediation:

1. **Canonicalize with `Path.resolve()`**: Converts the joined path to absolute form, resolving all `..` components and symlinks. This ensures `/etc/passwd` becomes `/etc/passwd` (absolute) and `../etc/passwd` also resolves to `/etc/passwd` (not left as a relative path that might bypass checks).

2. **Enforce containment with `is_relative_to()`**: After canonicalization, verify the resolved path is within `BASE_DIR` using path-component-aware comparison. This is safer than string prefix checks—`/srv/reports/documents-archive` would incorrectly pass a check like `str(path).startswith("/srv/reports/documents")`.

3. **Check the actual path used**: The resolved path is stored in `document_path` and that same variable is passed to `open()`, ensuring the security check cannot be bypassed by re-deriving the path.

An alternative using Flask's built-in helper: `flask.send_from_directory(BASE_DIR, filename)` applies `werkzeug.utils.safe_join()` internally and returns 404 on containment failure, eliminating the need for manual checks.

## Behaviour changes

**Request `/documents/download?file=q3-summary.pdf`**
- Before: Opens `/srv/reports/documents/q3-summary.pdf` ✓
- After: Resolves to `/srv/reports/documents/q3-summary.pdf`, passes `is_relative_to()` check, opens ✓ (no change)

**Request `/documents/download?file=/etc/passwd`**
- Before: Opens `/etc/passwd` ✗ (path traversal success)
- After: Resolves to `/etc/passwd`, fails `is_relative_to(BASE_DIR)`, returns 403 ✓ (blocked)

**Request `/documents/download?file=../../../etc/passwd`**
- Before: Joins to `/srv/reports/documents/../../../etc/passwd`, which `os.path.isfile()` resolves at check time, so open succeeds ✗
- After: Resolves to `/etc/passwd` during `Path.resolve()`, fails `is_relative_to()` check, returns 403 ✓ (blocked)

**Request `/documents/download?file=nested/path/report.pdf`**
- Before: Opens `/srv/reports/documents/nested/path/report.pdf` ✓
- After: Resolves to `/srv/reports/documents/nested/path/report.pdf`, passes `is_relative_to()`, opens ✓ (no change)

Legitimate requests to files within the `BASE_DIR` directory tree continue to work. Attempts to escape via absolute paths or `..` sequences are now rejected with a 403 Forbidden response.
