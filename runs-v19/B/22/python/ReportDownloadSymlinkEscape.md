## Verdict

CONFIRMED. The vulnerability is exploitable via a symlink planted inside the base directory that points to a file outside it.

## Source

User-controlled input `relative_path` from `request.args.get("path", "")` in `report_controller.py:5` flows to `open_report()` in `report_store.py:6`, where it is joined with `REPORT_ROOT` and opened at line 11.

## Fix

The vulnerability lies in two defects in `report_store.py`:

1. **`os.path.abspath()` does not follow symlinks** — it only resolves relative path components like `..` and `.`. A symlink at `/srv/app/reports/link → /etc/passwd` appears to be inside the directory when checked as a string.
2. **`str.startswith()` is not path-component aware** — it matches `/srv/app/documents-archive` as safe if the base is `/srv/app/documents` because `"/srv/app/documents-archive".startswith("/srv/app/documents")` returns `True`.

The fix uses `Path.resolve(strict=True)` to canonicalize the path (following symlinks) and `Path.is_relative_to()` to verify containment by path component. This ensures the final opened file is within the base directory, regardless of symlinks or traversal sequences.

### File: report_store.py

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

The fixed code changes three things:

1. **Use `Path` instead of `os.path`** — Python's `pathlib.Path` provides the `resolve()` method which follows symlinks and resolves relative path components to canonical form, and `is_relative_to()` which checks containment by path component.

2. **Canonicalize with `resolve(strict=True)`** — `(REPORT_ROOT / relative_path).resolve(strict=True)` combines joining and canonicalization in one step. The `strict=True` parameter ensures the path exists (raising `FileNotFoundError` if not), which is appropriate for a download operation where the file must already exist. `resolve()` follows symlinks to their target, so a symlink inside the directory that points outside will resolve to a location outside.

3. **Check containment with `is_relative_to()`** — `candidate.is_relative_to(REPORT_ROOT)` verifies that the canonical path stays within the base directory using proper path component comparison, not string prefix matching. This prevents a sibling directory like `/srv/app/documents-archive` from passing a check for `/srv/app/documents`.

The fix closes three attack vectors:

- **Symlink escape**: A symlink at `/srv/app/reports/link → /etc/passwd` resolves to `/etc/passwd`, which fails the `is_relative_to()` check.
- **Absolute path injection**: If `relative_path` is `/etc/passwd`, the `/` operator discards `REPORT_ROOT` and joins to `/etc/passwd`, which fails the containment check.
- **Relative traversal**: If `relative_path` is `../../etc/passwd`, it resolves to `/srv/app/etc/passwd` (or raises if that path doesn't exist), which fails the check if it resolves outside the base.

## Behaviour changes

- **Path type**: The function now uses `pathlib.Path` objects internally instead of strings. The return value of `open()` is unchanged (a file object).
- **Canonicalization**: `REPORT_ROOT` is now canonicalized once at module load time. This ensures a consistent base even if the filesystem root itself is a symlink.
- **Error on missing file**: `resolve(strict=True)` raises `FileNotFoundError` if the path does not exist or cannot be resolved. Previously, `os.path.abspath()` would succeed for any path (existing or not), and `open()` would raise the error. This moves the error earlier and makes it more predictable.
- **Error on escape**: The error type for path escape remains `PermissionError`, but the condition that triggers it is now robust against symlinks and traversal sequences.
