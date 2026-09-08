## Verdict

The path traversal vulnerability is confirmed and remediable. The code uses `os.path.join()` to construct a file path from user-supplied input without validating that the resolved path remains within the base directory. An attacker can supply an absolute path (e.g., `/etc/passwd`) to bypass the base directory entirely, or use traversal sequences like `../` to access files outside the intended directory.

## Source

HTTP query parameter `file` in `request.args.get("file")` (line 18) flows untrusted into `os.path.join()` at line 23, reaching the file open sink at line 28.

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

    # Resolve the joined path to absolute form, verifying it stays within BASE_DIR.
    base_path = Path(BASE_DIR).resolve()
    candidate_path = (base_path / filename).resolve()

    # Enforce containment within the base directory.
    if not candidate_path.is_relative_to(base_path):
        abort(403, description="Access to that file is not permitted")

    if not candidate_path.is_file():
        abort(404, description="Document not found")

    with open(candidate_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The fix resolves both the base directory and the candidate path to their absolute canonical forms using `Path.resolve()`, which resolves `.`, `..`, symlinks, and absolute path escapes. After resolution, `is_relative_to()` verifies that the candidate path is equal to or nested within the base directory by comparing path components (not as a string prefix, which is vulnerable to names like `/srv/reports/documents-archive`). The resolved path is then checked to ensure it is a file and used directly in the `open()` call.

Key changes:
- **Line 5**: Import `Path` from `pathlib`
- **Line 25-26**: Resolve base and candidate paths separately, ensuring absolute form
- **Line 28-29**: Verify containment with `is_relative_to()` and reject with 403 if outside base
- **Line 31**: Use the resolved path object (not the original filename) in the `is_file()` check
- **Line 34**: Pass the resolved path to `open()` instead of the unsafe `document_path`

The fix prevents attackers from accessing files via:
- Absolute paths: `/etc/passwd` fails containment check
- Traversal: `../../etc/passwd` resolves outside base and fails containment check
- Symlink escape: `resolve()` follows symlinks; the resolved target is checked for containment

## Behaviour changes

- **Security**: Path traversal and directory escape attacks are now blocked with a 403 response instead of silently granting access.
- **Error handling**: Invalid access attempts now return 403 (forbidden) instead of potentially exposing file-not-found status for sensitive paths.
- **Performance**: Minimal impact—one additional filesystem resolution call at request time.
- **Symlink handling**: The fix now properly resolves symbolic links, so legitimate symlink reads remain supported while symlink-based escapes are blocked.
