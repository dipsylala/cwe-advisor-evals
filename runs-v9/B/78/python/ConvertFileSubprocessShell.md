## Verdict

Exploitable. Confidence: medium (see assumptions - the hardened fix assumes a conventional Linux install path for the `libreoffice` binary, which should be confirmed against the deployment environment).

## Source

`request.form["filename"]` (Flask request form field, attacker-controlled) in `convert_document()`. The value is interpolated, unvalidated, directly into `input_path` (`f"{UPLOAD_DIR}/{filename}"`) and then into the shell command string `command`, which reaches `subprocess.run(command, shell=True, check=True)` at line 23. No validation, allowlist, or escaping occurs anywhere on this path, so shell metacharacters in `filename` (e.g. `; rm -rf /`, backticks, `$( )`) are interpreted by the shell the subprocess spawns.

## Fix

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
    # SAST FINDING: CWE-78 sink
    subprocess.run(command, shell=True, check=True)

    return send_file(output_path)
```

Fixed code:

```python
import re
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"
LIBREOFFICE_BIN = "/usr/bin/libreoffice"

# Secondary defence: restrict filenames to a safe charset with no path
# separators, so input_path/output_path cannot escape their directories
# and cannot smuggle option-like tokens into later processing.
SAFE_FILENAME = re.compile(r"[A-Za-z0-9._-]+")


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]
    if not SAFE_FILENAME.fullmatch(filename):
        return "Invalid filename", 400

    input_path = f"{UPLOAD_DIR}/{filename}"
    output_path = f"{OUTPUT_DIR}/{filename}.pdf"

    subprocess.run(
        [
            LIBREOFFICE_BIN,
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            OUTPUT_DIR,
            input_path,
        ],
        shell=False,
        check=True,
    )

    return send_file(output_path)
```

## Explanation

Running LibreOffice from a web endpoint is the endpoint's actual purpose, not an incidental wrapper around something a native Python library can do, so the remediation keeps the subprocess call and makes it safe rather than removing it. The command is rebuilt as an argument list passed with `shell=False`, so no shell is ever invoked to parse the string and shell metacharacters in `filename` lose their special meaning entirely - this closes the CWE-78 injection, which was the sole point of this finding. A `re.fullmatch()` allowlist (anchored with `fullmatch`, not `match()` against `^...$`, since `$` in Python also matches before a trailing newline) is added as the secondary defence layer the guidance calls for: it rejects path separators and any character outside `[A-Za-z0-9._-]`, so `filename` cannot be used to escape `UPLOAD_DIR`/`OUTPUT_DIR` or inject stray tokens. The LibreOffice binary is invoked by its absolute path rather than a bare command name, per the guidance's `PATH`-hijack defence, so a writable `PATH` entry earlier in the search order cannot substitute a different executable.

## Behaviour changes

- Requests with a `filename` outside `[A-Za-z0-9._-]+` (including any containing `/`, spaces, or unicode) now receive `400 Invalid filename` instead of reaching the subprocess call. This is a new rejection path; it is required to close CWE-78 as a defence-in-depth layer and to stop the same field from traversing out of `UPLOAD_DIR`/`OUTPUT_DIR`, but it will reject some previously-accepted legitimate filenames (e.g. ones with spaces) - the allowlist may need broadening for the real filename conventions in use, without reintroducing shell metacharacters or path separators.
- `libreoffice` is now invoked by the absolute path `/usr/bin/libreoffice` instead of resolving `libreoffice` off `PATH`. This is the guidance's recommended defence against a writable-`PATH` binary substitution attack. The exact path is an assumption (conventional Debian/Ubuntu install location) - if the deployment installs LibreOffice elsewhere (e.g. a snap or a different distro layout), this path must be corrected or the call will fail with `FileNotFoundError` where it previously succeeded.
- `shell=True` with a single command string is replaced by `shell=False` with an argument list. This is the core fix for CWE-78; no other change to what is executed, its arguments, or their order.
- `check=True` is preserved, so a failed conversion still raises `subprocess.CalledProcessError` exactly as before (Flask still turns this into a 500). The success path is unchanged: `send_file(output_path)` returns the same file it did originally, with no new output surfaced and none of the original output suppressed.
