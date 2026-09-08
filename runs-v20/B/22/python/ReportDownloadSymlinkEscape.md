## Verdict

Exploitable.

## Source

`report_controller.py`, `download_report()`: `request.args.get("path", "")` - an attacker-controlled query parameter, passed unmodified into `open_report(report_path)`.

## Fix

### File: report_store.py

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

`report_store.py`, `open_report()`, line 11 (sink: `open(candidate, "rb")`) joined the untrusted `relative_path` onto `REPORT_ROOT` with `os.path.join` and validated containment with `os.path.abspath(...).startswith(REPORT_ROOT)`. `abspath()` only collapses `.`/`..` and makes the path absolute - it never touches the filesystem, so it does not resolve a symlink. A path inside `REPORT_ROOT` whose final component is a symlink pointing outside it (e.g. a report entry that is actually a link to `/etc/passwd` or another tenant's file) passes the `startswith` check unchanged, because the string still begins with `REPORT_ROOT`, while the file that `open()` actually reads is the link's target outside the root. The same `startswith` check is also a raw string-prefix comparison, so a sibling directory such as `/srv/app/reports-archive` would incorrectly pass too, and `os.path.join` discards `REPORT_ROOT` entirely when `relative_path` is itself absolute (e.g. `/etc/passwd`), a case the original check happened to still reject only because `abspath` of an already-absolute path does not start with `REPORT_ROOT` - the symlink and sibling-directory cases were not caught.

The fix replaces `os.path.join` + `abspath` + string-prefix with `pathlib`: `(REPORT_ROOT / relative_path).resolve()` performs a real filesystem resolution, following any symlink components and collapsing `.`/`..`, and `candidate.is_relative_to(REPORT_ROOT)` performs a path-component-aware containment check rather than a string-prefix test. `REPORT_ROOT` itself is resolved once at import time so the comparison is between two canonical paths. This closes the symlink-escape path (the resolved target is compared, not the pre-resolution name), the sibling-directory bypass (`is_relative_to` respects path boundaries), and the absolute-path bypass (an absolute `relative_path` still resolves outside `REPORT_ROOT` and is rejected).

## Behaviour changes

- Exception type/message on a rejected path is unchanged (`PermissionError("report path escapes root")`); only the check that decides when it fires is stronger.
- A request for a path that does not exist previously reached `open()` and raised `FileNotFoundError`; `Path.resolve()` here is not called with `strict=True`, so a nonexistent path still falls through to `open()` and still raises `FileNotFoundError` - no change in observable failure mode for missing files.
- A path inside `REPORT_ROOT` whose final component is a symlink to a file outside `REPORT_ROOT` now raises `PermissionError` instead of being served - this is the vulnerability being closed, not an incidental change.
- No change to the function's return value (still a file handle from `open(..., "rb")`) or to the caller (`report_controller.py`) - it is unmodified.
