## Verdict

exploitable (confidence: high)

## Source

`request.args.get("filename")` at line 12 — the `filename` query parameter of `GET /reports/download`, fully attacker-controlled. It flows to the sink `open(report_path, "rb")` at line 16, where `report_path = os.path.join(REPORTS_DIR, filename)` (line 13).

`os.path.join()` discards the base directory entirely when the second segment is an absolute path (`os.path.join("/srv/app/reports", "/etc/passwd")` returns `/etc/passwd`), and it performs no normalization of `..` segments, so `filename=../../../../etc/passwd` or `filename=/etc/passwd` both resolve outside `REPORTS_DIR`. Nothing between the source and the sink canonicalizes the path or checks containment, so the trace confirms an unbroken, exploitable path.

Sink contract: `open()` returns a binary file handle that the handler reads in full and returns as the HTTP response body with `Content-Type: application/pdf`; it discards nothing; the mode argument (`"rb"`) is explicit and unchanged; on failure (`FileNotFoundError`, `PermissionError`, `IsADirectoryError`) it currently propagates as an unhandled exception (framework default 500).

## Fix

### File: OsPathJoinOpenFile.py

```python
import os
from pathlib import Path

from flask import Flask, request, abort

app = Flask(__name__)

REPORTS_DIR = Path("/srv/app/reports").resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    candidate = (REPORTS_DIR / filename).resolve()

    # SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    if not candidate.is_relative_to(REPORTS_DIR) or not candidate.is_file():
        abort(404)

    with open(candidate, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

`REPORTS_DIR` is now resolved once to its canonical absolute form at module load. The request-supplied `filename` is joined onto it with `pathlib`'s `/` operator and the result is resolved to its canonical form as well, following any symlinks and collapsing `..` segments. Before the file is opened, `candidate.is_relative_to(REPORTS_DIR)` performs a path-component-aware containment check (rejecting both `../../etc/passwd`-style traversal and an absolute override like `/etc/passwd`, since resolving either against `REPORTS_DIR` no longer lands the result inside it), and `candidate.is_file()` confirms the target exists and is a regular file. Only the resolved, checked `candidate` variable — never the raw `filename` — reaches `open()`, so the value that was validated is the value that is opened. This closes the traversal: no request value can any longer cause a path outside `REPORTS_DIR` to be read.

## Behaviour changes

- Added `abort(404)` on a failed containment or existence check. The original code had no such gate, so a traversal attempt or a missing filename previously either read an out-of-tree file (the vulnerability) or raised an uncaught `FileNotFoundError`/`IsADirectoryError` that surfaced as a framework 500. Both outcomes are replaced by a controlled 404, matching how Flask's own `send_from_directory()` reports a rejected or absent path. This is a necessary consequence of closing the weakness, not incidental scope creep.
- No change to the success path: a legitimate `filename` still resolves to the same file, is still opened in `"rb"` mode, and the response still returns the raw bytes with `Content-Type: application/pdf` exactly as before.

Assumptions: target Python is 3.9+ (`Path.is_relative_to()` requires 3.9); this is consistent with the rest of the codebase using modern Flask/`pathlib` idioms and no evidence was found narrowing the runtime further, so confidence is not lowered on this point. `flask.abort` is used as the standard Flask API for a short-circuit HTTP error response (same package already imported in the original file). Verification: `python -m py_compile` was run against the fixed file on a scratch copy and completed with no errors (exit 0); no test suite was available in the case directory to exercise a runtime check.
