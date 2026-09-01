## Verdict
The vulnerability is confirmed. Line 11 opens a file after performing an incomplete path canonicalization check that does not resolve symlinks.

## Source
```python
def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")  # Line 11: vulnerable open
```

The data flow: `download_report()` in report_controller.py calls `open_report()` with user-controlled `request.args.get("path", "")`, which is passed through to line 11.

## Fix
Replace `os.path.abspath()` with `os.path.realpath()` on line 7:

```python
def open_report(relative_path):
    candidate = os.path.realpath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
```

## Explanation
`os.path.abspath()` normalizes a path to absolute form but does not resolve symlinks. An attacker can create a symlink within the reports directory pointing to a file outside the root (e.g., `/srv/app/reports/link → /etc/passwd`). The `abspath()` check passes because the canonical path is still within `/srv/app/reports`, but `open()` then follows the symlink and accesses the target file outside the root directory.

`os.path.realpath()` resolves all symlinks to their true filesystem targets before canonicalization. The check `candidate.startswith(REPORT_ROOT)` now compares the symlink's dereferenced target against the root, correctly rejecting any symlink that points outside the allowed directory. This closes the symlink-escape variant of path traversal.
