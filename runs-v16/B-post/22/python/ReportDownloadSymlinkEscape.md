## Verdict

**Real issue confirmed.** The validation at line 8 is insufficient to prevent symlink-based path traversal. `os.path.abspath()` does not resolve symbolic links, and the `startswith()` containment check is not path-component-aware.

Exploitation scenario: An attacker creates a symlink `/srv/app/reports/link` pointing to `/etc/passwd`. When requesting `path=link`, the code resolves to `/srv/app/reports/link` (passes `startswith()` check) but `open()` follows the symlink and reads `/etc/passwd`.

## Source

`report_store.py`, line 11:

```python
def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")  # Vulnerable: insufficient validation
```

The check uses `abspath()` (no symlink resolution) and `startswith()` (not path-component-aware containment).

## Fix

```python
from pathlib import Path

REPORT_ROOT = Path("/srv/app/reports").resolve()


def open_report(relative_path):
    candidate = (REPORT_ROOT / relative_path).resolve(strict=True)
    if not candidate.is_relative_to(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

Changes:
1. Use `pathlib.Path` instead of `os.path` functions
2. Resolve `REPORT_ROOT` once at module load to canonical form with symlinks resolved
3. Use `Path.resolve(strict=True)` to canonicalize the joined path and resolve symlinks; `strict=True` raises `FileNotFoundError` if the file does not exist, which is correct for a read operation
4. Replace `startswith()` with `is_relative_to()` for path-component-aware containment (Python 3.9+)
5. Pass the resolved `candidate` variable directly to `open()` — the value that was checked is the value that is opened

## Explanation

The original code attempted to prevent path traversal but failed on two fronts:

1. **Symlink bypass**: `os.path.abspath()` normalizes relative paths and `.` and `..` sequences but does not follow symbolic links. An attacker who plants a symlink within the allowed directory can cause it to point outside, bypassing the check. `Path.resolve()` follows all symlinks and produces the true canonical path.

2. **String-prefix bypass**: The containment check `candidate.startswith(REPORT_ROOT)` compares paths as strings without understanding path components. A path like `/srv/app/reports-secret` would pass the check even though it is outside the intended directory. `is_relative_to()` correctly verifies that a path is a sub-path of another by component, not by string prefix.

The fix resolves both the joined path and the root directory to canonical form before comparison, ensuring that symlinks are followed and the containment check is robust. `strict=True` on `resolve()` enforces that the file must exist, which is correct for a download operation.

## Behaviour changes

- **Exception on missing file**: If the requested file does not exist, `resolve(strict=True)` raises `FileNotFoundError` instead of silently failing at `open()`. This is correct for a download operation — the client now receives an explicit error rather than a confusing failure later.
- **Symlinks followed**: Legitimate symlinks within `/srv/app/reports` that point to files also within the allowed tree will continue to work; symlinks pointing outside the tree will be blocked.
- **Sibling-directory protection**: Paths like `../documents-archive/notes.txt` will now correctly raise `PermissionError` instead of potentially succeeding with a string-prefix bypass.
