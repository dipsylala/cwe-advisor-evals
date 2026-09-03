## Verdict

Path traversal vulnerability confirmed. The code constructs a file path from user input without validating that the final path remains within the intended base directory. An attacker can exploit this by providing an absolute path (which `os.path.join` discards) or path traversal sequences like `../` to access files outside `/srv/reports/documents`.

## Source

**File:** `evals/cases/22/python/AbsolutePathDiscardsBaseJoin/document_download.py`  
**Line:** 23  
**Vulnerable Code:**
```python
document_path = os.path.join(BASE_DIR, filename)
```

The vulnerability: `os.path.join(BASE_DIR, filename)` returns `filename` unchanged when `filename` is an absolute path. Additionally, `filename` containing `../` sequences can traverse up the directory tree before the check.

## Fix

```python
@documents_bp.route("/documents/download")
def download_document():
    """Return the contents of a report stored under BASE_DIR.

    Example: GET /documents/download?file=q3-summary.pdf
    """
    filename = request.args.get("file")
    if not filename:
        abort(400, description="Missing 'file' query parameter")

    # Construct the full path and resolve it to its absolute, normalized form
    document_path = os.path.realpath(os.path.join(BASE_DIR, filename))
    base_dir_real = os.path.realpath(BASE_DIR)

    # Verify the resolved path is within BASE_DIR
    if not (document_path == base_dir_real or document_path.startswith(base_dir_real + os.sep)):
        abort(404, description="Document not found")

    if not os.path.isfile(document_path):
        abort(404, description="Document not found")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation

The fix uses `os.path.realpath()` to resolve the joined path to its canonical absolute form, which:
- Normalizes `../` and `./` sequences
- Resolves symlinks
- Converts relative paths to absolute paths

After resolution, the code checks that the final path is either equal to the base directory or starts with the base directory plus a separator. This prevents:
1. **Absolute path injection:** Requests like `?file=/etc/passwd` resolve to `/etc/passwd`, which fails the `startswith` check
2. **Directory traversal:** Requests like `?file=../../etc/passwd` resolve outside the base directory and fail the check
3. **Symlink escapes:** The `realpath()` call follows symlinks to their targets, ensuring the actual file is within the base directory

The path validation happens before any file operations, so unauthorized access attempts are rejected with a 404 error that doesn't distinguish between "file outside base" and "file not found," avoiding information disclosure.
