## Verdict

Confirmed. `open_report` in `report_store.py` builds a candidate path from attacker-controlled input and validates it with `os.path.abspath()` plus a `str.startswith()` prefix check before opening it. Neither operation resolves symlinks, so a symlink placed inside `REPORT_ROOT` that points outside it will pass validation (its lexical path still starts with `REPORT_ROOT`) and then be followed by `open()` at line 11, handing the caller a file handle to whatever the symlink target is. The prefix check also has a secondary weakness: it compares raw strings, so a sibling directory such as `/srv/app/reports_evil` would also satisfy `startswith(REPORT_ROOT)`.

## Source

`report_controller.py` line 5: `report_path = request.args.get("path", "")` - an HTTP query parameter, fully attacker-controlled, passed unmodified into `open_report(report_path)` on line 6.

## Fix

```python
import os

REPORT_ROOT = os.path.realpath("/srv/app/reports")


def open_report(relative_path):
    candidate = os.path.realpath(os.path.join(REPORT_ROOT, relative_path))

    if candidate != REPORT_ROOT and not candidate.startswith(REPORT_ROOT + os.sep):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation

`os.path.abspath()` only performs lexical normalization (collapsing `..` and `.` segments and making the path absolute); it never touches the filesystem, so it cannot detect that a path component is a symlink pointing elsewhere. `os.path.realpath()` does resolve symlinks (and any `..`/`.` segments) by consulting the filesystem, so if `relative_path` names a symlink inside `REPORT_ROOT` - or traverses through one - `candidate` becomes the link's real, resolved target. Comparing that resolved target against `REPORT_ROOT` (itself resolved once at module load, in case the root directory itself is reached via a symlink) means the containment check reflects where the file actually lives, not just how the path was spelled.

The boundary check is also tightened from a bare `startswith(REPORT_ROOT)` to require either an exact match or a match against `REPORT_ROOT + os.sep`. Without the separator, a resolved path like `/srv/app/reports_evil/secret` would incorrectly pass the check because the string `/srv/app/reports_evil/secret` starts with the string `/srv/app/reports`; requiring the trailing separator (or exact equality for the root itself) ensures only genuine descendants of `REPORT_ROOT` are accepted.

Because `realpath` resolves the entire chain of symlinks and `..` segments before comparison, this closes both the symlink-escape path (a link inside the root pointing outside it) and the classic `..`-based traversal in a single check, without needing to special-case either.
