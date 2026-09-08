## Verdict

Confirmed. `open_report` in `report_store.py` builds `candidate` with `os.path.abspath`, which only normalizes `..`/`.`/separators textually and never resolves symlinks. If any component under `/srv/app/reports` is a symlink (or gets swapped for one) pointing outside the report root, `abspath` still returns a string that lexically starts with `REPORT_ROOT`, the containment check passes, and `open()` then follows the symlink and reads the external target. The check is also a bare string-prefix test, so a sibling directory that merely shares the root as a prefix (e.g. `/srv/app/reports-shared/...`) would incorrectly pass too.

## Source

`report_controller.download_report` reads the untrusted `path` request parameter (`request.args.get("path", "")`) and passes it straight to `open_report`, which joins it under `REPORT_ROOT` and opens it - the attacker-controlled `relative_path`/`candidate` is the tainted value reaching the `open()` sink at line 11.

## Fix

### File: report_store.py
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

`os.path.realpath` resolves `..`, `.`, and - critically - symlinks by consulting the filesystem, so `REPORT_ROOT` and `candidate` are now compared as their true, fully-resolved locations. A symlink placed inside the reports directory that points outside of it resolves to its real external target before the containment check runs, so the check now catches it instead of being fooled by the pre-resolution path string.

The boundary check is also tightened from a raw `str.startswith(REPORT_ROOT)` to require either an exact match or a match followed by `os.sep`. This closes the secondary gap where a directory merely sharing `REPORT_ROOT` as a string prefix (not a path-component ancestor) would previously pass. Together these changes make the check reflect the actual resolved filesystem location of the target file, not just a textual property of the requested path, before that path is handed to `open()`.

A test that reproduces the original bug: create `/srv/app/reports/link -> /etc/passwd` (or any symlink whose target resolves outside `REPORT_ROOT`) and call `open_report("link")`. Before the fix, `abspath` leaves the symlink unresolved, the prefix check passes, and `open()` returns a handle onto `/etc/passwd`. After the fix, `realpath` resolves the symlink to `/etc/passwd` first, the containment check fails, and `PermissionError` is raised instead.
