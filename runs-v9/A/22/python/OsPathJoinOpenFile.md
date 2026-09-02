## Verdict

Confirmed. The `filename` query parameter is attacker-controlled and is joined onto a trusted base directory with `os.path.join`, then opened directly. `os.path.join` does not neutralize `..` segments or an absolute path component, so a request such as `/reports/download?filename=../../../../etc/passwd` (or an absolute path, which `os.path.join` will substitute for the base entirely on POSIX) lets an attacker read arbitrary files reachable by the process, outside `REPORTS_DIR`.

## Source

`filename = request.args.get("filename")` (line 12) - untrusted HTTP query parameter, flowing unvalidated into `os.path.join(REPORTS_DIR, filename)` (line 13) and then into `open(report_path, "rb")` (line 16).

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

    # Reject path separators / traversal in the supplied name outright;
    # only a bare filename is a legitimate report name.
    candidate = os.path.basename(filename)
    if candidate != filename or candidate in ("", ".", ".."):
        abort(400)

    report_path = os.path.realpath(os.path.join(REPORTS_DIR, candidate))

    # Belt-and-braces: confirm the resolved path is still inside REPORTS_DIR
    # (guards against symlinks and any other resolution surprises).
    if os.path.commonpath([report_path, REPORTS_DIR_REAL]) != REPORTS_DIR_REAL:
        abort(403)

    if not os.path.isfile(report_path):
        abort(404)

    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix applies defense in depth rather than relying on a single check:

1. `os.path.basename(filename)` strips any directory components. Comparing the result back against the original value (`candidate != filename`) rejects any input that contained a path separator (`/`, or `\` on Windows) or was an absolute path, instead of silently truncating it to something that looks plausible but isn't what the caller asked for. This alone stops the common `../../etc/passwd` traversal payload and rejects absolute paths, which `os.path.join` would otherwise substitute for the base directory entirely.
2. The explicit `candidate in ("", ".", "..")` check rejects the remaining edge cases that `basename` alone does not filter (an empty string, or `.`/`..` themselves, which have no path separator to strip).
3. `os.path.realpath` is applied to both the candidate path and the base directory, and `os.path.commonpath` confirms the resolved candidate still lives under the resolved base. This catches symlinks inside `REPORTS_DIR` that could otherwise point outside it, and is deliberately kept as a second, independent check rather than the only check - a single containment check on an unresolved path can be bypassed by symlink tricks that basename filtering alone would miss.
4. `os.path.isfile` before opening turns a missing-file case into a clean 404 instead of an unhandled exception, and avoids attempting to open directories or special files.

Together these ensure the file ultimately opened is always a direct child of `REPORTS_DIR`, with no traversal, absolute-path substitution, or symlink escape possible, while preserving the original functionality of serving a named report file from that directory.
