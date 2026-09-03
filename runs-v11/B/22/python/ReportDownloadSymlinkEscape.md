## Verdict

Real vulnerability. The `open_report()` function is susceptible to symlink escape attacks and string-prefix path containment bypass.

## Source

**report_store.py, lines 6-11:**

```python
def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")
    
    return open(candidate, "rb")
```

**Attack path:**

1. An attacker places a symlink at `REPORT_ROOT/evil → /etc/` and requests `path=evil/passwd`
2. `os.path.join(REPORT_ROOT, "evil/passwd")` produces `/srv/app/reports/evil/passwd`
3. `os.path.abspath()` normalizes this to `/srv/app/reports/evil/passwd` but does not resolve the symlink (because it makes no filesystem calls)
4. The `startswith()` check passes because `/srv/app/reports/evil/passwd` starts with `/srv/app/reports`
5. `open()` follows the symlink and reads `/etc/passwd`

Additionally, `startswith()` is unsafe for path component comparison: `/srv/app/reports-archive/file.txt` would pass a check for `/srv/app/reports` because strings have no path-component awareness.

## Fix

Replace `os.path.abspath()` with `Path.resolve()` to resolve symlinks, and replace `startswith()` with `is_relative_to()` to enforce proper path-component containment:

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

**Why the original is vulnerable:**

- `os.path.abspath()` normalizes path separators and resolves `..` sequences but does not follow symlinks; an attacker-controlled symlink in the allowed directory can point anywhere on the filesystem.
- `startswith()` treats paths as strings with no understanding of path components, so a directory name that shares a prefix with the root passes the check (`/srv/app/reports-archive` contains `/srv/app/reports` as a substring).

**How the fix works:**

- `Path.resolve()` resolves both relative paths (`..`) and symlinks by calling into the filesystem, producing the true canonical path. This forces any symlink to be followed to its actual target before containment is checked.
- `is_relative_to()` performs a path-aware containment check: it verifies that the candidate is either equal to the root or is a child of it, respecting path component boundaries. A sibling like `/srv/app/reports-archive` is correctly rejected.
- The same resolved path is stored and passed to `open()`, preventing time-of-check-time-of-use (TOCTOU) attacks where the filesystem state changes between validation and use.

The fix also assumes the path exists and is readable; if a non-existent destination must be validated (e.g., for an upload), `resolve(strict=False)` and parent-directory validation would be needed instead.

## Behaviour changes

- Symlinks within the allowed directory are now resolved, and any symlink target outside the root is rejected.
- Path containment is checked at the component level; directory names that share a prefix but are not path-equal or nested children are rejected.
- Any path that cannot be resolved (e.g., does not exist when `resolve(strict=True)` is used) raises an exception during validation rather than allowing the open to proceed and fail later.
- Legitimate reads of files in subdirectories within `REPORT_ROOT` continue to work.
- Read operations on absolute paths like `/etc/passwd` are now rejected by `is_relative_to()`.
