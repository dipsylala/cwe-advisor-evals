## Verdict
exploitable

## Source
`request.args.get("path", "")` in report_controller.py:5 - user-supplied path component

## Fix

**Vulnerable code:**
```python
import os

REPORT_ROOT = os.path.abspath("/srv/app/reports")

def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")
    
    return open(candidate, "rb")  # Line 11: vulnerable to symlink escape
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
The vulnerability exists because `os.path.abspath()` normalizes relative path components like `..` but does not follow symbolic links. An attacker can place a symlink inside REPORT_ROOT pointing to a file outside the allowed directory. The path check passes because the symlink itself is within the root directory, but `open()` follows the symlink to access files outside the intended directory. The fix uses `Path.resolve()` which canonicalizes the path AND follows symlinks to their true destination, ensuring the final resolved path is checked. The containment check is also upgraded from string prefix matching (`startswith()`) to path-component-aware comparison (`is_relative_to()`), which prevents prefix collisions like `/srv/app/documents-archive` matching a base of `/srv/app/documents`.

## Behaviour changes
None. The function still returns a file handle to the same destination when called with valid paths. The key difference is that symlink escapes are now properly detected and rejected at the security boundary (line 9) rather than being silently followed by the file open operation.
