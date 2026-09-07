## Verdict

Exploitable

## Source

`request.args.get("path", "")` in report_controller.py (line 5) flows through `download_report()` to `open_report()` in report_store.py (line 6) without proper symlink canonicalization.

## Fix

### File: report_store.py

```python
from pathlib import Path

REPORT_ROOT = Path("/srv/app/reports")


def open_report(relative_path):
    candidate = (REPORT_ROOT / relative_path).resolve(strict=True)
    if not candidate.is_relative_to(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation

The original code used `os.path.abspath()` to canonicalize the joined path, which does not follow symbolic links or validate containment correctly. An attacker could create a symlink inside `/srv/app/reports/` pointing to any file outside the directory (e.g., `/etc/passwd`), and the containment check `candidate.startswith(REPORT_ROOT)` would pass because it only does string prefix matching without path-component awareness. When `open()` follows the symlink, the attacker gains read access to arbitrary files on the system.

The fix replaces `os.path.abspath()` with `Path.resolve(strict=True)`, which follows symlinks and resolves relative path components (`.` and `..`) to their actual canonical locations. It also replaces the vulnerable string `.startswith()` check with `is_relative_to()`, which properly validates path containment by comparing path components rather than string prefixes. Using `strict=True` is appropriate here since this is a download operation where the file must already exist; it raises `FileNotFoundError` if the resolved path does not exist. The fix ensures that:

1. Symlinks inside the allowed directory that point outside are detected and rejected
2. Path traversal attempts like `../etc/passwd` are caught
3. String prefix matching vulnerabilities (e.g., `/srv/app/reports-backup/` matching a prefix of `/srv/app/reports/`) are eliminated

## Behaviour changes

- **Import change**: Added `from pathlib import Path` and changed `REPORT_ROOT` from a string to a `Path` object. This is required for using the `Path.resolve()` and `is_relative_to()` methods.
- **Exception type for non-existent files**: With `resolve(strict=True)`, if the resolved path does not exist, the code now raises `FileNotFoundError` instead of proceeding to `open()`. This is the correct behavior for a read operation where the file must exist before serving it; it provides earlier detection of invalid paths.
- **No change to return value or error handling**: The function still returns a file object on success and raises `PermissionError` on containment violations. The `FileNotFoundError` for non-existent files is an additional safety check not present in the original.
