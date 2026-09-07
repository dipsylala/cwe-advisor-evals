## Verdict

Exploitable. Untrusted `filename` from `request.form["filename"]` flows directly into a shell-concatenated command string passed to `subprocess.run()` with `shell=True`, allowing arbitrary OS command execution.

## Source

```python
filename = request.form["filename"]
input_path = f"{UPLOAD_DIR}/{filename}"
output_path = f"{OUTPUT_DIR}/{filename}.pdf"

command = (
    f"libreoffice --headless --convert-to pdf "
    f"--outdir {OUTPUT_DIR} {input_path}"
)
# Line 23: SINK
subprocess.run(command, shell=True, check=True)
```

Attack example: `filename="test.doc; rm -rf /"` would execute the destructive command after the document conversion.

## Fix

### File: ConvertFileSubprocessShell.py

```python
import subprocess
import os

from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/data/uploads"
OUTPUT_DIR = "/var/data/converted"


@app.route("/convert", methods=["POST"])
def convert_document():
    """Convert an uploaded document to PDF using the installed LibreOffice CLI."""
    filename = request.form["filename"]
    
    # Validate filename to prevent path traversal
    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename != filename:
        return "Invalid filename", 400
    
    input_path = os.path.join(UPLOAD_DIR, safe_filename)
    output_path = os.path.join(OUTPUT_DIR, f"{safe_filename}.pdf")
    
    # Use subprocess with argument list and shell=False to prevent OS command injection
    subprocess.run([
        "libreoffice",
        "--headless",
        "--convert-to", "pdf",
        "--outdir", OUTPUT_DIR,
        input_path
    ], check=True)
    
    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix eliminates the shell injection vulnerability by replacing the shell-concatenated command string with a subprocess argument list and `shell=False`. When subprocess receives an argument list instead of a shell string, the OS executes libreoffice directly with those arguments without shell interpretation, making metacharacter injection impossible. The filename is validated using `os.path.basename()` to strip any directory path components and reject attempts at path traversal; if the result differs from the original filename, the request is rejected. Path construction is changed to `os.path.join()` for safer handling. The fix preserves the original return value (`send_file(output_path)`), maintaining the application contract.

## Behaviour changes

**Filename validation:** Added rejection of filenames containing path components (e.g., `../file`, `subdir/file`). Requests with such filenames now return HTTP 400 instead of attempting conversion. This prevents directory traversal attacks that could access or convert files outside the upload directory.

**Path construction:** Changed from f-string concatenation to `os.path.join()`, which uses the OS-appropriate path separator and is more robust.

**No shell invocation:** The subprocess call no longer uses a shell, so the command line is not re-parsed by sh/bash, eliminating shell metacharacter interpretation entirely.

**Return value:** Unchanged—the function still returns `send_file(output_path)` on successful conversion.
