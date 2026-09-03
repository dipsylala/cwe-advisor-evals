## Verdict
CONFIRMED. The code is vulnerable to path traversal because `os.path.join()` discards the base directory when the `filename` parameter is an absolute path. An attacker can supply a filename like `/etc/passwd` to read arbitrary files outside the intended directory.

## Source
The vulnerability exists at line 23 of `document_download.py`:

```python
document_path = os.path.join(BASE_DIR, filename)
```

`os.path.join()` returns the last absolute path component when any argument is absolute. If `filename` starts with `/`, the function returns `filename` unchanged, ignoring `BASE_DIR` entirely.

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

    # Reject absolute paths
    if os.path.isabs(filename):
        abort(400, description="Invalid file path")
    
    # Join and resolve the path
    document_path = os.path.join(BASE_DIR, filename)
    document_path = os.path.abspath(document_path)
    base_dir_abs = os.path.abspath(BASE_DIR)
    
    # Verify the resolved path is within BASE_DIR
    if not document_path.startswith(base_dir_abs + os.sep) and document_path != base_dir_abs:
        abort(400, description="Invalid file path")

    if not os.path.isfile(document_path):
        abort(404, description="Document not found")

    with open(document_path, "rb") as f:
        data = f.read()

    return data, 200, {"Content-Type": "application/octet-stream"}
```

## Explanation
The fix applies three layers of defense:

1. **Reject absolute paths**: `os.path.isabs(filename)` prevents attackers from bypassing the base directory by supplying paths starting with `/`.

2. **Resolve the path**: `os.path.abspath()` normalizes the path, removing `.` and `..` sequences that might otherwise escape the directory (e.g., `/srv/reports/documents/subdir/../../etc/passwd`).

3. **Verify containment**: After normalization, the code verifies that the resolved path starts with the base directory path. The check `document_path.startswith(base_dir_abs + os.sep)` ensures the file is strictly within the directory (not a sibling with a similar name), and the fallback `document_path != base_dir_abs` handles the edge case where someone tries to read the directory itself.

Together, these checks ensure that only files within `/srv/reports/documents` can be accessed, regardless of how the attacker crafts the `file` parameter.
