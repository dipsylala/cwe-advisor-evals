## Verdict

Confirmed. `filename` comes from an untrusted HTTP query parameter and is joined into a filesystem path with `os.path.join()`, then opened directly. `os.path.join()` does not neutralize `..` segments or absolute paths, so a value such as `../../etc/passwd` (or an absolute path like `/etc/passwd`, which `os.path.join` will substitute for the base entirely) lets a request read arbitrary files outside `REPORTS_DIR` that the process can access.

## Source

```python
filename = request.args.get("filename")
report_path = os.path.join(REPORTS_DIR, filename)
```
(`OsPathJoinOpenFile.py`, lines 12-13) — `filename` is attacker-controlled input from the Flask request's query string, with no validation before use.

## Fix

```python
import os
from flask import Flask, request, abort

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"
REPORTS_DIR_REAL = os.path.realpath(REPORTS_DIR)


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    if not filename:
        abort(400)

    # Reject path separators / traversal in the supplied name up front.
    if os.path.basename(filename) != filename:
        abort(400)

    candidate = os.path.join(REPORTS_DIR, filename)
    real_path = os.path.realpath(candidate)

    # Confirm the resolved path stays within REPORTS_DIR before opening it.
    if os.path.commonpath([REPORTS_DIR_REAL, real_path]) != REPORTS_DIR_REAL:
        abort(403)

    if not os.path.isfile(real_path):
        abort(404)

    with open(real_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix applies two independent layers so that no single check has to carry the whole defense:

1. **Reject structure before it reaches the filesystem API.** `os.path.basename(filename) != filename` is true whenever `filename` contains a `/` (or, on Windows, a `\` or drive letter), which rejects both `../` traversal sequences and absolute-path payloads outright. This also blocks the `os.path.join` absolute-path-override behavior, since a rejected value never reaches `os.path.join` in a form that could be absolute.

2. **Verify containment on the resolved path (belt-and-suspenders).** `os.path.realpath()` resolves `..`, symlinks, and any residual normalization, and `os.path.commonpath()` confirms the resolved path is still a descendant of the resolved `REPORTS_DIR`. This catches cases the basename check alone might miss (e.g. a symlink placed inside `REPORTS_DIR` that points outside it) and fails closed (`403`) rather than silently falling back to an unchecked path.

`os.path.isfile()` after the containment check avoids leaking whether a directory exists at that location and prevents attempting to read a non-regular file. Returning `400`/`403`/`404` rather than propagating an exception avoids leaking filesystem details (stack traces, absolute paths) in the response.

This does not rely on stripping or sanitizing the value — a value that fails either check is rejected outright rather than rewritten, which avoids the class of bug where sanitization turns a malicious input into a different, still-valid-but-wrong path.
