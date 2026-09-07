## Verdict
CONFIRMED: Path traversal vulnerability via symlink escape. The code uses `os.path.abspath()` which does not resolve symlinks, allowing an attacker to access files outside `REPORT_ROOT` through a symlink placed within the directory.

## Source
`report_controller.py` calls `open_report()` with untrusted user input (`request.args.get("path")`). The `open_report()` function in `report_store.py` performs a path traversal check using `os.path.abspath()` and `startswith()`, but this check is bypassed when the path contains a symlink because `os.path.abspath()` does not resolve symlinks to their targets.

Attack: A symlink `/srv/app/reports/link_to_secret` → `/etc/passwd` passes the `startswith(REPORT_ROOT)` check but opens the actual target file outside the restricted directory when `open()` is called.

## Fix
### File: report_store.py

```python
import os

REPORT_ROOT = os.path.abspath("/srv/app/reports")


def open_report(relative_path):
    candidate = os.path.realpath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation
Replace `os.path.abspath()` with `os.path.realpath()` on line 7. The key difference is that `os.path.realpath()` resolves all symlinks in the path to their actual targets, while `os.path.abspath()` only normalizes the path without following symlinks.

With this fix, if an attacker passes a path containing a symlink that points outside `REPORT_ROOT`, the `realpath()` call will resolve it to its actual target, and the `startswith()` check will correctly reject it. For example, `/srv/app/reports/link_to_secret` will be resolved to `/etc/passwd`, which fails the startswith check and raises `PermissionError`.

This ensures that symlinks cannot be used to escape the restricted directory, closing the CWE-22 vulnerability.
