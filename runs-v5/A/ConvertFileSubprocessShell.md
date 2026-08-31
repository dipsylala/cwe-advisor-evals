## Verdict

Confirmed. `filename` comes from the untrusted request body (`request.form["filename"]`) and flows unmodified into a shell command string that is executed via `subprocess.run(command, shell=True, check=True)`. An attacker who controls `filename` can append shell metacharacters (`;`, `|`, `&&`, backticks, `$()`, whitespace, etc.) to run arbitrary commands with the privileges of the Flask process. The same value is also concatenated directly into `input_path`/`output_path`, so it is exposed to path traversal as well, but the reported sink at line 23 is the OS command injection.

## Source

`filename = request.form["filename"]` (line 14) - attacker-controlled form field, flows through `input_path`/`output_path` and the `command` f-string into the `subprocess.run(..., shell=True)` sink at line 23.

## Fix

```python
import os
import re
import subprocess

from flask import Flask, abort, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"

# Only allow a safe, unambiguous filename: no path separators, no leading dot,
# no shell metacharacters.
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]

    # Reject anything that isn't a bare filename (blocks traversal and
    # neutralizes command-injection payloads before they reach subprocess).
    if not SAFE_FILENAME_RE.match(filename) or os.path.basename(filename) != filename:
        abort(400, description="Invalid filename")

    input_path = os.path.join(UPLOAD_DIR, filename)
    output_path = os.path.join(OUTPUT_DIR, f"{filename}.pdf")

    if not os.path.isfile(input_path):
        abort(404)

    # No shell involved: argv is passed as a list, so no string is ever
    # interpreted by a shell. "--" stops libreoffice from treating a
    # filename that happens to start with "-" as an option.
    subprocess.run(
        [
            "libreoffice",
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            OUTPUT_DIR,
            "--",
            input_path,
        ],
        shell=False,
        check=True,
    )

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

The original code built a single shell command string by interpolating `filename` directly and handed it to `subprocess.run(..., shell=True)`. `shell=True` spawns `/bin/sh -c "<command>"`, so any shell metacharacter present in `filename` (`;`, `|`, `&`, backticks, `$( )`, newlines, whitespace that splits into extra arguments, etc.) is interpreted by the shell rather than treated as literal filename text - that is the command-injection sink.

The fix removes the shell entirely: `subprocess.run` is called with an argument list and `shell=False` (the default, made explicit here), so the OS executes `libreoffice` directly and each element of the list is passed to it as a single literal argument with no shell parsing step - metacharacters in `filename` can no longer break out of the intended argument.

An argument list alone does not fully close the door, though: `libreoffice` still parses its own argv, so a filename like `-headless-something` could be read as an option by the target program rather than as a filename, and a value like `../../etc/passwd` would still let the process read outside `UPLOAD_DIR`. Three additional, independent controls handle this:

- A strict allowlist regex constrains `filename` to a safe character set with no path separators, closing both traversal and most flag-like payloads at the source, before it is used to build any path or command.
- `os.path.basename(filename) != filename` is a second-line check confirming the value contains no directory components after the regex, and `os.path.join` builds the real filesystem path instead of string interpolation.
- The literal `--` argument passed to LibreOffice marks the end of options, so even a value that begins with `-` (already rejected by the regex, but defense-in-depth if the pattern is ever loosened) cannot be reinterpreted as a flag by the target program.

`os.path.isfile` on the resolved input path guards against attempting to convert a nonexistent file, turning a missing-file condition into a controlled 404 instead of an uncaught `CalledProcessError`.
