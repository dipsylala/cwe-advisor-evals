## Verdict

**Confirmed exploitable.**

## Source

User-controlled path from `request.args.get("path")` in `report_controller.py:5` flows to `open_report()` at line 6.

## Fix

Replace the vulnerable containment check and open operation in `report_store.py`:

**Vulnerable code (lines 6–11):**
```python
def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

**Fixed code:**
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

The vulnerability is a symlink-based path traversal. `os.path.abspath()` normalizes but does not resolve symbolic links, so a symlink inside REPORT_ROOT pointing outside the directory passes the `startswith()` check. When `open()` is called, the symlink is followed, bypassing the containment check.

The fix uses `Path.resolve(strict=True)`, which resolves all symbolic links to their actual targets before validation. The containment check is then performed on the fully-resolved path. Additionally, `is_relative_to()` is used instead of `startswith()` for path-component-aware comparison (so `/srv/app/documents-archive` does not match a base of `/srv/app/documents`).

`strict=True` is appropriate here because the path must exist for a file read to succeed; it will raise `FileNotFoundError` if the resolved path does not exist, which is the intended behavior for a download operation.

## Behaviour changes

- Path resolution now follows symlinks, so a symlink inside REPORT_ROOT that points outside will be detected and rejected.
- String prefix matching is replaced with path-component-aware containment checking.
- A request for a path that does not exist (including one where the symlink target does not exist) raises `FileNotFoundError` instead of `PermissionError`; this is expected and correct for a download.
