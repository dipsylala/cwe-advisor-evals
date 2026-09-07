## Verdict

The finding is valid. `os.path.join()` (and Path's `/` operator) both discard the base directory when the second argument is an absolute path. An attacker can pass `/etc/passwd` as the `file` parameter, causing `os.path.join(BASE_DIR, "/etc/passwd")` to return `/etc/passwd` instead of a path within BASE_DIR. The subsequent `os.path.isfile()` check passes, and the file is opened and read without containment validation, enabling arbitrary file access outside the intended directory.

## Source

**Location:** Line 23 in `document_download.py`

**Entry point:** `filename = request.args.get("file")` (line 18) - untrusted user input from query parameter

**Sink:** `os.path.join(BASE_DIR, filename)` (line 23) - vulnerable join operation that discards base on absolute paths

**Data flow:**
1. `filename` from `request.args.get("file")` - untrusted input
2. `os.path.join(BASE_DIR, filename)` - vulnerable join, discards BASE_DIR if filename is absolute
3. `os.path.isfile(document_path)` (line 25) - checks existence but not containment
4. `open(document_path, "rb")` (line 28) - opens file without verifying it is within BASE_DIR

**Exploit example:** `GET /documents/download?file=/etc/passwd` reads the system password file.

## Fix

### File: document_download.py

```python
"""Document download endpoint for the internal reports portal."""

from pathlib import Path

from flask import Blueprint, abort, request

BASE_DIR = "/srv/reports/documents"
BASE_DIR_RESOLVED = Path(BASE_DIR).resolve()

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
        # Resolve the joined path - this raises FileNotFoundError if the file doesn't exist
        document_path = (Path(BASE_DIR) / filename).resolve(strict=True)
    except FileNotFoundError:
        abort(404, description="Document not found")

    # Verify the resolved path is within BASE_DIR
    if not document_path.is_relative_to(BASE_DIR_RESOLVED):
        abort(403, description="Access denied")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The fix implements canonicalize-then-contain validation as described in the CWE-22 guidance:

1. **Resolve the joined path** - `(Path(BASE_DIR) / filename).resolve(strict=True)` converts the path to absolute canonical form, resolving symlinks and relative references (`.`, `..`). The `strict=True` parameter raises `FileNotFoundError` if the file does not exist, replacing the separate `os.path.isfile()` check.

2. **Verify containment** - `document_path.is_relative_to(BASE_DIR_RESOLVED)` performs path-component-aware containment checking. This prevents escape via:
   - Absolute paths: `/etc/passwd` is not relative to `/srv/reports/documents`
   - Traversal sequences: `../../etc/passwd` resolves to `/srv/etc/passwd`, which is not relative to `/srv/reports/documents`
   - Similar-named sibling directories: `../documents-archive/file.txt` resolves to `/srv/reports/documents-archive/file.txt`, which is not relative to `/srv/reports/documents` (string prefix matching would fail here, but `is_relative_to()` checks component boundaries)

3. **Use the resolved path** - The `open()` call uses `document_path` (the resolved Path object), never the original untrusted `filename`, breaking taint after validation.

4. **Pre-compute base resolution** - `BASE_DIR_RESOLVED` is computed once at module load to avoid recalculating the canonical form on every request.

The fix uses Python 3.9+ `Path.is_relative_to()` for proper path-component-aware comparison instead of string prefix matching.

Syntax validation: passed with `python -m py_compile`.

## Behaviour changes

**Security:** Paths containing `..`, `/`, or starting with `/` are now rejected with HTTP 403 instead of being processed.

**HTTP responses:**
- Legitimate file in BASE_DIR: HTTP 200 (unchanged behavior)
- File not found: HTTP 404 (unchanged behavior)
- File exists but outside BASE_DIR: HTTP 403 (new - previously allowed unauthorized access)
- Missing query parameter: HTTP 400 (unchanged behavior)

**Performance:** No measurable change. Base directory resolution is computed once at import time; per-request overhead is equivalent (one `Path.resolve()` call instead of two `os.path` operations).

**Compatibility:** Requires Python 3.9+ for `Path.is_relative_to()`. No framework changes needed; Flask's `abort()` and `request.args` behavior unchanged.
