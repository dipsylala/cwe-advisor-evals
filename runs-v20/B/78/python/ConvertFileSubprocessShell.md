## Verdict

Exploitable. CWE-78, OS Command Injection.

- Location: `ConvertFileSubprocessShell.py`, line 23 (sink: `subprocess.run(command, shell=True, check=True)`).
- Confidence: high.

## Source

`filename = request.form["filename"]` (line 14) - an attacker-controlled value taken directly from an unauthenticated POST form field, with no validation or sanitization applied anywhere before it reaches the sink.

Data flow: `filename` -> `input_path = f"{UPLOAD_DIR}/{filename}"` (line 15) -> interpolated into the `command` f-string (lines 18-21) -> `subprocess.run(command, shell=True, check=True)` (line 23). Because the whole command is built as a single string and executed with `shell=True`, any shell metacharacter in `filename` (e.g. `; `, `` ` ``, `|`, `$( )`, `&&`) is interpreted by `/bin/sh` rather than treated as part of a filename, giving arbitrary command execution with the privileges of the Flask process.

## Fix

### File: ConvertFileSubprocessShell.py

```python
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"
LIBREOFFICE_BIN = "/usr/bin/libreoffice"


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{OUTPUT_DIR}/{filename}.pdf"

    command = [
        LIBREOFFICE_BIN,
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        OUTPUT_DIR,
        input_path,
    ]
    subprocess.run(command, shell=False, check=True)

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

Running a document through the LibreOffice headless converter is the feature the endpoint exists for, not an incidental step with a native Python equivalent - there is no standard-library or well-known-package substitute that drives LibreOffice's conversion engine, so the command has to stay and be executed safely rather than removed. The fix keeps `subprocess.run()` but replaces the single interpolated shell string with an explicit argument list and sets `shell=False`, so no shell is ever invoked and no metacharacter in `filename` is given a chance to be parsed as shell syntax - the value is always passed to `execve` as one opaque argument (embedded inside `input_path`), never as command syntax. `--outdir` and `--convert-to pdf` remain fixed, non-attacker-controlled arguments exactly as before. The binary is also invoked by its absolute path (`/usr/bin/libreoffice`) per the CWE-78 guidance's least-privilege/PATH-hijack principle, so a writable `PATH` entry earlier than the real binary cannot substitute a different executable.

Argument injection (CWE-88) does not apply here: the only attacker-influenced argument, `input_path`, is always prefixed with the literal `UPLOAD_DIR` path segment, so it can never begin with `-` and cannot be misread as a flag by `libreoffice`.

## Behaviour changes

- Command construction changed from a single shell string to a list, and `shell=True` became `shell=False` - this is the change that closes the injection; it does not alter what is executed (same binary, same flags, same operands) or what `subprocess.run()` returns/raises.
- `check=True` is preserved unchanged, so `CalledProcessError` is still raised on a non-zero exit and the caller's failure behaviour is unaffected.
- Neither `stdout` nor `stderr` is captured in the fix, matching the original, which also let both stream to the parent process's console - no new output is surfaced and none of the original's is newly discarded.
- The binary is now invoked via an absolute path (`/usr/bin/libreoffice`) instead of relying on `PATH` resolution. This is an assumption: the exact install location of the LibreOffice CLI depends on the deployment environment (e.g. `/usr/bin/libreoffice` on common Debian/Ubuntu packaging vs. a different path on other distributions or a manual install). If the target environment installs it elsewhere, `LIBREOFFICE_BIN` must be updated to match before deploying; this does not weaken the fix if wrong, it only need correcting to a valid path.
- Path traversal in `filename` (e.g. `../../etc/passwd`) is unchanged from the original and is out of scope for this CWE-78 finding (it is a CWE-22 concern); no validation was added for it here to avoid conflating two separate findings.

Verification: the fixed file was copied to a scratch location and checked with `python -m py_compile` (CPython 3.13.12) with no errors or warnings, confirming it is syntactically valid. `subprocess.run`, `subprocess`, and all Flask names used (`Flask`, `request`, `send_file`) are unchanged from the original file's imports; no new import or third-party API was introduced.
