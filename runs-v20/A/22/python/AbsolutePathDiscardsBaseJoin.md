## Verdict

Confirmed. `document_path = os.path.join(BASE_DIR, filename)` at line 23 builds the path from an unvalidated, request-controlled `filename`. `os.path.join` discards all preceding components as soon as it hits an absolute path segment, so a request like `GET /documents/download?file=/etc/passwd` produces `document_path == "/etc/passwd"`, entirely outside `BASE_DIR`. A relative traversal payload such as `../../etc/passwd` is not stopped either, since nothing normalizes or bounds-checks the result before it is opened.

## Source

`filename = request.args.get("file")` (line 18) - the `file` query parameter on `GET /documents/download`, read directly from the Flask request and passed unmodified into the path-building sink.

## Fix

### File: document_download.py

```python
"""Document download endpoint for the internal reports portal."""

import os

from flask import Blueprint, abort, request

BASE_DIR = "/srv/reports/documents"
BASE_DIR_REAL = os.path.realpath(BASE_DIR)

documents_bp = Blueprint("documents", __name__)


@documents_bp.route("/documents/download")
def download_document():
    """Return the contents of a report stored under BASE_DIR.

    Example: GET /documents/download?file=q3-summary.pdf
    """
    filename = request.args.get("file")
    if not filename:
        abort(400, description="Missing 'file' query parameter")

    # Reject any path-like input outright: a bare filename is expected, so an
    # absolute path or a path containing directory separators (which os.path.join
    # would otherwise honor, discarding BASE_DIR entirely for an absolute input,
    # or "../" segments for a relative one) is never legitimate here.
    candidate = filename.replace("\\", "/")
    if os.path.isabs(filename) or "/" in candidate or filename in (".", ".."):
        abort(400, description="Invalid 'file' query parameter")

    document_path = os.path.realpath(os.path.join(BASE_DIR, filename))

    # Belt-and-braces containment check: confirm the resolved path is still
    # inside BASE_DIR (guards against symlinks or any other normalization surprise).
    if os.path.commonpath([document_path, BASE_DIR_REAL]) != BASE_DIR_REAL:
        abort(400, description="Invalid 'file' query parameter")

    if not os.path.isfile(document_path):
        abort(404, description="Document not found")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The root cause is twofold: (1) `os.path.join` silently drops `BASE_DIR` whenever `filename` is an absolute path, and (2) even for relative input, nothing prevented `../` segments from walking out of `BASE_DIR` before the file was opened.

The fix rejects the request outright, before any path is built, if `filename` is absolute, contains a `/` (or backslash, normalized first so a Windows-style separator can't slip past a forward-slash-only check), or is `.`/`..`. Since the endpoint's own docstring and example show it is meant to take a bare filename (e.g. `q3-summary.pdf`), this is a legitimate format constraint on the value, not a security-only allowlist - any input containing a path separator is illegitimate for this endpoint regardless of exploitability.

As defense in depth, the resulting path is also resolved with `os.path.realpath` and checked with `os.path.commonpath` against the realpath of `BASE_DIR`, so that even an unexpected normalization or a symlink inside the documents directory can't cause a read outside the intended tree. The existing `os.path.isfile` check and file-read logic are unchanged.
