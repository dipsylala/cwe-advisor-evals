## Verdict

CWE-22 (Path Traversal) - **exploitable**. Confidence: high.

## Source

`filename = request.args.get("filename")` (line 12) - an unvalidated Flask query-string
parameter, fully attacker-controlled.

Sink: `open(report_path, "rb")` (line 16), where `report_path = os.path.join(REPORTS_DIR, filename)`
(line 13).

`filename` flows unmodified from the query string into `os.path.join()` and then straight into
`open()` with no canonicalization and no containment check in between. Two distinct routes reach
outside `REPORTS_DIR`:

- Relative traversal: `filename="../../etc/passwd"` joins to `/srv/app/reports/../../etc/passwd`,
  which `open()` follows without complaint.
- Absolute override: `filename="/etc/passwd"` - `os.path.join()` discards the base entirely when
  the second segment is an absolute path, so `os.path.join("/srv/app/reports", "/etc/passwd")`
  returns `/etc/passwd` outright.

## Fix

Vulnerable code:

```python
import os

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = "/srv/app/reports"


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    report_path = os.path.join(REPORTS_DIR, filename)

    # SAST FINDING: CWE-22 reported here. Sink is the next statement.
    with open(report_path, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

Fixed code:

```python
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)

REPORTS_DIR = Path("/srv/app/reports").resolve()


@app.route("/reports/download")
def download_report():
    filename = request.args.get("filename")
    if filename is None:
        return "Missing filename", 400

    candidate = (REPORTS_DIR / filename).resolve()
    if not candidate.is_relative_to(REPORTS_DIR) or not candidate.is_file():
        return "Not found", 404

    with open(candidate, "rb") as report_file:
        contents = report_file.read()

    return contents, 200, {"Content-Type": "application/pdf"}


if __name__ == "__main__":
    app.run()
```

## Explanation

The join and the containment check are now applied to the same variable: `candidate` is built by
joining `filename` under the resolved `REPORTS_DIR` and then canonicalized with `Path.resolve()`,
which follows symlinks and collapses `..` segments (unlike `os.path.normpath()`/`os.path.abspath()`,
neither of which touches the filesystem). `candidate.is_relative_to(REPORTS_DIR)` then verifies
containment by path component rather than by string prefix, so a sibling directory such as
`/srv/app/reports-archive` cannot pass. Because the check runs after resolution, it catches both
attack routes identified above: a `../`-relative escape resolves outside `REPORTS_DIR` and fails
containment, and an absolute `filename` such as `/etc/passwd` - which still overrides the base the
same way under `pathlib`'s `/` operator as it did under `os.path.join()` - resolves to itself and
likewise fails containment. Only `candidate`, the checked value, is passed to `open()`; the raw
`filename` never reaches the sink.

## Behaviour changes

- **Missing `filename`**: the original passed `None` straight into `os.path.join()`, which raises
  `TypeError` (unhandled -> Flask 500). The fix returns an explicit `400 Missing filename` for that
  case. Necessary because the new code must inspect `filename` before it can build `candidate`.
- **Traversal or absolute-path attempt**: the original would follow the path and serve whatever
  file is at that location (the vulnerability). The fix returns `404 Not found` instead of serving
  the file. This is the containment check working as intended, not incidental.
- **Non-existent (but in-bounds) file**: the original let `open()` raise `FileNotFoundError`
  (unhandled -> Flask 500) for a missing report. The fix checks `candidate.is_file()` and returns
  an explicit `404 Not found` instead. This follows the language guidance's remediation steps
  (confirm `is_file()` before opening) and turns an unhandled exception into a controlled response;
  it does not change what data is ever returned to the caller.
- **`import os` replaced with `from pathlib import Path`**: `os.path.join()` is no longer used
  anywhere in the file, so the import was swapped for the one the fix actually needs rather than
  left dangling.
- Response body, status, and headers for a legitimate in-bounds request are unchanged: the same
  bytes are read from the same resolved file and returned with `200` and
  `Content-Type: application/pdf`.
