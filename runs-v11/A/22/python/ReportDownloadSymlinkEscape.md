## Verdict

The code is vulnerable to symlink-based path traversal. The use of `os.path.abspath()` normalizes the path but does not resolve symlinks, allowing an attacker to create a symlink under the restricted directory that points outside of it. The path validation check using `startswith()` would pass, but the file operation would follow the symlink and access files outside the intended directory.

## Source

```python
import os

REPORT_ROOT = os.path.abspath("/srv/app/reports")

def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Fix

```python
import os

REPORT_ROOT = os.path.abspath("/srv/app/reports")

def open_report(relative_path):
    candidate = os.path.realpath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(os.path.realpath(REPORT_ROOT)):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation

The vulnerability arises because `os.path.abspath()` normalizes relative path components but does not resolve symbolic links. An attacker can place a symlink under the restricted `/srv/app/reports/` directory pointing to sensitive files outside the root, such as `/srv/app/reports/symlink -> /etc/passwd`. The validation `candidate.startswith(REPORT_ROOT)` would incorrectly pass since the string path still begins with the root, but the subsequent `open()` call would follow the symlink and expose files outside the intended directory.

The fix replaces `os.path.abspath()` with `os.path.realpath()`, which resolves both relative path components and symbolic links to their canonical, absolute paths. This ensures that after symlink resolution, the path truly remains within the restricted directory. The comparison is also updated to use the real path of `REPORT_ROOT` itself to ensure a consistent, symlink-resolved comparison.

This prevents the symlink escape by validating the actual target path after all symbolic links are dereferenced, not just the path string before following symlinks.
