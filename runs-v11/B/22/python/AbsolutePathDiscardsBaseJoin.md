## Verdict

Exploitable path traversal. The vulnerability is real and requires remediation.

## Source

Line 18: `filename = request.args.get("file")` receives untrusted user input from the query parameter without validation.

## Fix

Replace the vulnerable code at lines 23–31 with:

```python
from pathlib import Path

@documents_bp.route("/documents/download")
def download_document():
    """Return the contents of a report stored under BASE_DIR.

    Example: GET /documents/download?file=q3-summary.pdf
    """
    filename = request.args.get("file")
    if not filename:
        abort(400, description="Missing 'file' query parameter")

    # Resolve the joined path to absolute form and verify containment
    base_path = Path(BASE_DIR)
    candidate = (base_path / filename).resolve()
    
    if not candidate.is_relative_to(base_path):
        abort(403, description="Access denied")

    if not candidate.is_file():
        abort(404, description="Document not found")

    with open(candidate, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

Require `from pathlib import Path` at the top of the file.

## Explanation

The original code uses `os.path.join(BASE_DIR, filename)` without validation. This is unsafe because `os.path.join()` discards the base directory when the second argument is an absolute path (e.g., `/etc/passwd`) or contains relative traversal sequences (e.g., `../../etc/passwd`). An attacker can exploit this to read any file on the system.

The fix:
1. Converts the base directory to a `Path` object for consistent path handling.
2. Joins the user input with the base using the `/` operator (which has identical semantics to `os.path.join()` but works with `Path` objects).
3. Calls `resolve()` to canonicalize the path, eliminating `..` and symbolic link indirection to produce an absolute filesystem path.
4. Verifies the resolved path stays within the base directory using `is_relative_to()`, which is path-component-aware (unlike string prefix matching).
5. Checks that the candidate is a file before opening it.
6. Opens only the validated path, never the original user input.

This eliminates the traversal vector: absolute paths and traversal sequences are detected and rejected after canonicalization, before any file operation.

## Behaviour changes

**Legitimate requests remain unaffected:**
- A request for `q3-summary.pdf` joins to `/srv/reports/documents/q3-summary.pdf`, resolves (no change), passes containment check, and opens successfully.
- Subdirectory access like `reports/q3-summary.pdf` works identically: the path is joined, resolved to `/srv/reports/documents/reports/q3-summary.pdf`, verified, and opened.

**Traversal attempts now return 403 Forbidden instead of potentially succeeding:**
- `../../etc/passwd` resolves to `/etc/passwd` (outside the base), fails `is_relative_to()`, returns 403.
- `/etc/passwd` is treated as absolute by `/` operator, resolves to `/etc/passwd`, fails containment, returns 403.
- Both cases that previously would read arbitrary files now reject the request.

**Return codes:**
- `400` (Missing parameter) - unchanged.
- `403` (Access denied) - new, replaces the previous behavior of silently allowing traversal.
- `404` (Document not found) - unchanged, returned for non-existent or non-file paths within the allowed directory.
