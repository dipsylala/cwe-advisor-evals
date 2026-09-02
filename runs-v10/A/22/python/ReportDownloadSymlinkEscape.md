## Verdict
**Vulnerable.** The path traversal check uses `os.path.abspath()`, which normalizes `.` and `..` but does not resolve symlinks. An attacker can create a symlink under `/srv/app/reports/` pointing to a file outside the restricted directory; the validation passes because the symlink path itself starts with `REPORT_ROOT`, but `open()` on line 11 follows the symlink and reads the target file outside the restriction.

## Source
Line 11 in `report_store.py`: the `open(candidate, "rb")` call occurs after insufficient validation. The check at lines 8-9 verifies `candidate.startswith(REPORT_ROOT)`, but `candidate` is computed using `os.path.abspath()` on line 7, which does not resolve symlinks.

## Fix
Replace `os.path.abspath()` with `os.path.realpath()` to resolve symlinks before validating the path:

```python
import os

REPORT_ROOT = os.path.realpath("/srv/app/reports")


def open_report(relative_path):
    candidate = os.path.realpath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

Apply `os.path.realpath()` to both `REPORT_ROOT` (line 3) and the computed `candidate` path (line 7). `os.path.realpath()` expands symbolic links and normalizes the path to its actual target, ensuring the validation check cannot be bypassed by symlinks.

## Explanation
**Why the original code is vulnerable:**
`os.path.abspath()` performs string-based path normalization (resolving `.` and `..`), but leaves symlinks unresolved. An attacker controls the report filename via the `path` parameter in `report_controller.py`. By creating a symlink like `/srv/app/reports/etc_passwd_link -> /etc/passwd`, the attacker's request for `etc_passwd_link` passes the `startswith(REPORT_ROOT)` check because the symlink's path is under the root, but the `open()` call resolves the symlink and reads the target file outside the restriction.

**Why the fix works:**
`os.path.realpath()` resolves all symlinks in the path to their actual targets before returning the canonical path. If a symlink points outside `REPORT_ROOT`, the resulting canonical path will not start with `REPORT_ROOT`, and the validation will correctly reject it. This closes the symlink escape attack surface.
