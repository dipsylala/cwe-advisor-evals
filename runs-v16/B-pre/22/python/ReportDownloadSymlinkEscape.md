## Verdict
Exploitable

## Source
`request.args.get("path", "")` in report_controller.py, line 5 → open_report() parameter

## Fix

**Vulnerable code:**
```python
import os

REPORT_ROOT = os.path.abspath("/srv/app/reports")

def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):  # UNSAFE: string prefix, not path-component aware
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

**Fixed code:**
```python
from pathlib import Path

REPORT_ROOT = Path("/srv/app/reports").resolve()

def open_report(relative_path):
    candidate = (REPORT_ROOT / relative_path).resolve()
    if not candidate.is_relative_to(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation
The original code uses `str.startswith()` to check whether the resolved path stays within the approved directory. String prefix matching is not path-component aware: a sibling directory like `/srv/app/reports-secret/file.txt` passes the check against base `/srv/app/reports` because the string matches the prefix, even though the path is not inside that directory. The fixed code replaces the string check with `Path.is_relative_to()`, which is path-component aware and rejects paths outside the allowed directory. Additionally, `Path.resolve()` replaces `os.path.abspath()` to ensure symlinks are followed during canonicalization, closing symlink-based escape attempts.

## Behaviour changes
- **Module-level canonicalization**: `REPORT_ROOT` is now resolved to an absolute canonical path once at import time, rather than inside each call. This is a performance improvement and does not affect correctness since the root directory is server-controlled and immutable.
- **Symlink resolution**: The `candidate` path is now resolved with symlink following, whereas the original code did not follow symlinks. This is a security improvement: the original code would accept a symlink inside `REPORT_ROOT` pointing outside it, while the fixed code correctly rejects such attempts. The behavior change is that a legitimate symlink inside the reports directory pointing to an external location would now be rejected, which is the correct security behavior.
- **Error message unchanged**: The exception raised and its message remain the same, preserving compatibility with exception handling in calling code.
