## Verdict

- **cwe_id**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **location**: `report_store.py`, line 11 (`open(candidate, "rb")`)
- **verdict**: exploitable
- **confidence**: high

## Source

- **source**: `request.args.get("path", "")` in `report_controller.py` line 5 - an attacker-controlled query parameter, passed unchanged as `report_path` into `open_report(report_path)` at line 6.
- **sink**: `open(candidate, "rb")` in `report_store.py` line 11.
- **data flow**: `report_path` enters `open_report(relative_path)` and is joined to `REPORT_ROOT` with `os.path.join`, then "canonicalized" with `os.path.abspath` (line 7). The result is checked with `candidate.startswith(REPORT_ROOT)` (line 8) before being opened at line 11. `os.path.abspath()` performs no filesystem access, so it never resolves symbolic links - a symlink located inside `/srv/app/reports` (e.g. `reports/evil -> /etc/passwd`) produces a `candidate` string that still starts with `REPORT_ROOT` and passes the check, but `open()` at line 11 follows the symlink at open time and reads the out-of-root target. The `startswith` comparison is also a raw string prefix test, not path-component-aware, so a sibling directory such as `/srv/app/reports-secret/...` would pass the same check.

## Fix

No third-party library is required; the fix uses the standard-library `pathlib` API named in the Python guidance.

Vulnerable code (`report_store.py`):

```python
import os

REPORT_ROOT = os.path.abspath("/srv/app/reports")


def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):  # non-symlink-aware, non-component-aware check
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

Fixed code:

```python
from pathlib import Path

REPORT_ROOT = Path("/srv/app/reports").resolve()


def open_report(relative_path):
    candidate = (REPORT_ROOT / relative_path).resolve(strict=True)
    if not candidate.is_relative_to(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation

The fix replaces `os.path.abspath()` with `Path.resolve()`, which makes a filesystem call and therefore follows symbolic links as well as `.`/`..` segments, so a symlink planted inside the report root that points outside it is resolved to its real, out-of-root target before the containment check runs rather than after. `resolve(strict=True)` is used because this sink is a download of a file that must already exist, matching the read case in the Python guidance; it raises `FileNotFoundError` for a missing target, which is the same exception `open()` would have raised previously, so error handling upstream is unaffected. The raw `str.startswith()` prefix comparison is replaced with `Path.is_relative_to()`, which compares by path component rather than by character prefix, closing the secondary bypass where a sibling directory name (e.g. `reports-secret`) shares a string prefix with `REPORT_ROOT` but is not actually contained in it. The resolved `candidate` is the same value passed to `open()`, so the value that was checked is the value that is opened.

## Behaviour changes

- `REPORT_ROOT` and `candidate` are now `pathlib.Path` objects instead of `str`; `open()` accepts a `Path` directly so this does not change the call's behavior.
- Symlinks inside the report root that point outside it are now followed during canonicalization and correctly rejected by the containment check, instead of being canonicalized as if they were regular files at their in-root location - this closes the escape and is the point of the fix.
- A candidate path that does not exist now raises `FileNotFoundError` at the `resolve(strict=True)` call instead of at the subsequent `open()` call. The exception type and timing relative to the containment check are unchanged from the caller's perspective (the file still did not open), so no new exception type needs to be handled upstream.
- `import os` was removed as it is no longer used after switching to `pathlib`; no other import or dependency was added.
- All other behavior - the return value (a binary file handle), the `PermissionError` raised on an out-of-root path, and the absence of any other validation - is unchanged.
