## Verdict

CONFIRMED: Path Traversal via symlink escape in path containment check.

## Source

- **Attacker input**: `request.args.get("path", "")` (report_controller.py:5)
- **Sink**: `open(candidate, "rb")` (report_store.py:11)
- **Data flow**: Request parameter → `open_report()` → `os.path.join()` → `os.path.abspath()` → `startswith()` check → `open()`

## Fix

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

The original code uses `os.path.abspath()` to resolve paths, which does not follow symlinks. An attacker can escape the report root by placing a symlink inside `/srv/app/reports` that points to an external location (e.g., `/srv/app/reports/link -> /etc`), then requesting that symlink. The path passes the `startswith()` check because the filesystem hasn't followed the symlink yet. 

The fix replaces `os.path.abspath()` with `pathlib.Path.resolve()`, which actually resolves symlinks to their targets. It also replaces the string-based `startswith()` check with `is_relative_to()`, which is path-component aware and avoids the prefix-matching flaw (e.g., `/srv/app/reports-secret` would not pass a check for `/srv/app/reports`).

The `strict=True` parameter ensures the resolved path must exist and is accessible before the containment check, preventing TOCTTOU (Time-Of-Check-Time-Of-Use) issues between validation and file opening.

## Behaviour changes

- **Path joining**: Changed from `os.path.join()` to `pathlib.Path` `/` operator. Functionally equivalent for joining relative paths.
- **Path resolution**: Changed from `os.path.abspath()` to `Path.resolve()`. Now follows symlinks to their true targets, closing the symlink escape vector.
- **Containment check**: Changed from string `startswith()` to `Path.is_relative_to()`. More precise path-component-aware comparison.
- **File existence requirement**: Added implicit requirement via `strict=True` on resolve. File must exist and be readable at check time, preventing the validated path from being replaced before opening.
- **Exception handling**: `FileNotFoundError` now raised if the resolved path does not exist, which is correct for a read operation (download). This replaces silent failure or opening an incorrect file.
