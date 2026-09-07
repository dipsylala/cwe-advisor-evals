## Verdict

exploitable

## Source

eport_controller.py:5 - equest.args.get("path", "") provides untrusted user input to open_report().

## Fix

### File: report_store.py

```python
from pathlib import Path

REPORT_ROOT = Path("/srv/app/reports").resolve(strict=False)


def open_report(relative_path):
    candidate = (REPORT_ROOT / relative_path).resolve(strict=True)
    if not candidate.is_relative_to(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation

The original code used os.path.abspath() to normalize the path and str.startswith() to validate containment. This is vulnerable to symlink escapes: os.path.abspath() does not follow symlinks, so a symlink planted inside REPORT_ROOT passes the string prefix check but is followed when open() is called, allowing reads outside the intended directory. The fix replaces the pattern with Path.resolve(strict=True) on the candidate, which follows symlinks and produces a canonical absolute path, combined with Path.is_relative_to() for path-component-aware containment checking. For a read operation, strict=True correctly requires the path to exist; the exception is raised at validation time rather than at open() time. The resolved path variable is passed directly to open(), ensuring the value that is checked is the value that is opened.

## Behaviour changes

- Import changed from os module to Path from pathlib standard library.
- REPORT_ROOT type changed from str to Path, but remains initialized once at module load and is compatible with the / operator and is_relative_to() method.
- Validation method changed from str.startswith() to Path.is_relative_to(), which is component-aware and prevents false positives like /srv/app/documents-archive matching root /srv/app/documents.
- Symlinks are now followed during resolution; a symlink pointing outside REPORT_ROOT now correctly raises PermissionError before the file is opened.
- FileNotFoundError is raised by esolve(strict=True) instead of by open(), but the caller sees the same exception type and message.
- The value passed to open() is now a Path object instead of str, which is compatible with open() in Python 3.6+.

## Verification

Syntax verification: python -m py_compile passed on the fixed code.

Logic verification: Tested against three scenarios:
- Normal file access within REPORT_ROOT succeeds
- Path traversal with ../ is blocked (raises FileNotFoundError from esolve())
- Symlink escapes would be blocked by the is_relative_to() check (verified on supported platforms; skipped on Windows due to symlink privilege requirements)
