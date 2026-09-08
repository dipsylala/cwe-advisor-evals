## Verdict

exploitable (confidence: high)

- cwe_id: CWE-22
- location: document_download.py, line 23 (sink), line 18 (source)

## Source

`request.args.get("file")` at line 18 - the `file` query parameter on `GET /documents/download` is attacker-controlled and reaches the sink unvalidated.

## Fix

### File: document_download.py

```python
"""Document download endpoint for the internal reports portal."""

from pathlib import Path

from flask import Blueprint, abort, request

BASE_DIR = Path("/srv/reports/documents").resolve()

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
        document_path = (BASE_DIR / filename).resolve(strict=True)
    except OSError:
        abort(404, description="Document not found")

    if not document_path.is_relative_to(BASE_DIR) or not document_path.is_file():
        abort(404, description="Document not found")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

`os.path.join(BASE_DIR, filename)` discards `BASE_DIR` entirely whenever `filename` is an absolute path (`os.path.join('/srv/reports/documents', '/etc/passwd')` returns `/etc/passwd`), and even for a relative `filename` the join never checks that the result stays under `BASE_DIR` - `../../etc/passwd` resolves outside it. The fix joins with `Path.__truediv__` (which has the identical absolute-path-discards-base behavior, so the join alone still isn't a control) and then calls `.resolve(strict=True)` to canonicalize the result - following symlinks and collapsing `..` - and raises `FileNotFoundError`/`OSError` if the target doesn't exist, which is caught and turned into the same 404 the original code already returned for a missing file. The resolved path is then checked with `document_path.is_relative_to(BASE_DIR)`, a path-component-aware containment test (unlike a raw string prefix, which `/srv/reports/documents-archive` would pass against a `/srv/reports/documents` base). Only a path that both resolves inside `BASE_DIR` and exists as a regular file is opened, and the same `document_path` variable produced by the check is the one passed to `open()`, so nothing is re-derived from the raw request value after validation.

## Behaviour changes

- A request whose `file` value is absolute or contains `../` sequences that escape `BASE_DIR` now returns 404 instead of leaking the arbitrary file's contents. This is the vulnerability being closed, not a side effect.
- A request for a file reached via a symlink that points outside `BASE_DIR` now returns 404 where the original would have served it (the original never resolved symlinks at all); this is a tightening of the existing containment intent, not a new restriction the sink didn't already imply.
- `os.path.isfile(document_path)` is replaced by `document_path.is_file()` on the resolved `Path` object - same check, same semantics, no behavior difference for a legitimate request.
- The `not filename` / 400 branch, the 404-on-missing-file response, the binary read, and the response tuple (`data, 200, {"Content-Type": "application/octet-stream"}`) are all unchanged.
- No new arguments, dropped parameters, or altered return values beyond the above; the sink's read-and-return-bytes contract is preserved for every legitimate request.

## Verification

`python -m py_compile` on the fixed file (Python 3.13.12): no errors.

Additionally exercised the resolve/containment logic standalone against a scratch directory tree standing in for `BASE_DIR`: a legitimate subdirectory file resolved and passed containment; a `../`-relative traversal to a sibling file, an absolute path to the same sibling file, a request for a nonexistent file, and a traversal into a same-prefix sibling directory (`../testbase-other/...`) all correctly resulted in the 404 branch.

Every name introduced by the fix - `pathlib.Path`, `Path.resolve()`, `Path.is_relative_to()` (3.9+), `Path.is_file()` - is Python standard library and was confirmed by the successful compile and the standalone execution above.

Assumption: the target Python version is assumed to be 3.9+ for `Path.is_relative_to()`, per the loaded CWE-22/python guidance's own recommendation of that API; no version constraint was given in the source file.
