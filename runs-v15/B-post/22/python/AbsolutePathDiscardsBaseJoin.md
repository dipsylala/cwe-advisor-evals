## Verdict

Real - confirmed path traversal via absolute path discarding the base directory in `os.path.join()`.

## Source

User-supplied `filename` parameter from `request.args.get("file")` at line 18.

## Fix

Replace the unsafe `os.path.join()` pattern with `pathlib.Path` operations, canonicalize the result with `resolve(strict=True)`, and enforce containment with `is_relative_to()` before opening the file.

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

    # Resolve the joined path to absolute canonical form and verify containment
    try:
        document_path = (BASE_DIR / filename).resolve(strict=True)
    except (FileNotFoundError, ValueError):
        abort(404, description="Document not found")

    # Enforce that the resolved path stays within the base directory
    if not document_path.is_relative_to(BASE_DIR):
        abort(403, description="Access denied")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The original code uses `os.path.join(BASE_DIR, filename)` which is vulnerable because `os.path.join()` (and `pathlib.Path` `/` operator) discard the base path if the second operand is an absolute path. An attacker supplying `filename=/etc/passwd` causes `os.path.join()` to return `/etc/passwd` directly, bypassing the intended containment to `BASE_DIR`.

The fix converts `BASE_DIR` to a `pathlib.Path` object and uses the `/` operator for path construction. Immediately after joining, `resolve(strict=True)` canonicalizes the path to its absolute form and raises `FileNotFoundError` if the file does not exist. The critical addition is `is_relative_to(BASE_DIR)`, which verifies the canonicalized path is a descendant of the base directory by path-component-aware comparison, not string prefix matching. An absolute path like `/etc/passwd` will fail this check and trigger a 403 rejection. A traversal attempt like `../../../etc/passwd` will resolve to an absolute path outside `BASE_DIR` and also be rejected.

The fix preserves the original contract: legitimate files under `BASE_DIR` are still served, non-existent files still return 404, and the response is still binary. The `ValueError` exception from `resolve()` is caught alongside `FileNotFoundError` for robustness, though it rarely occurs in practice.

## Behaviour changes

- Absolute paths in `filename` (e.g., `/etc/passwd`) now return 403 instead of being opened
- Relative traversals outside `BASE_DIR` (e.g., `../../etc/passwd`) now return 403 instead of being opened
- Non-existent files return 404 (unchanged); the `resolve(strict=True)` call replaces the earlier `os.path.isfile()` check with the same outcome for legitimate requests
- Symbolic links are resolved to their targets; a symlink inside `BASE_DIR` pointing outside will be rejected by `is_relative_to()` if the target is outside
