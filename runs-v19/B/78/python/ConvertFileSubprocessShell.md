## Verdict

Exploitable. User-controlled filename flows directly into a shell command string executed with `shell=True`, allowing arbitrary OS command injection.

## Source

Line 14: `filename = request.form["filename"]` - untrusted user input from Flask form data

## Fix

### File: ConvertFileSubprocessShell.py

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

    subprocess.run(
        ["libreoffice", "--headless", "--convert-to", "pdf",
         "--outdir", OUTPUT_DIR, input_path],
        shell=False, check=True
    )

    return send_file(output_path)


if __name__ == "__main__":
    app.run()
```

## Explanation

The vulnerability occurs because the command is constructed as a string using f-strings with untrusted user input (`filename`), then executed with `shell=True`. This allows an attacker to inject shell metacharacters to execute arbitrary commands. The fix converts the command from a single string executed through a shell into an argument array passed directly to the process (`shell=False`), eliminating the shell interpretation step. Each component of the command (the executable, flags, and arguments) becomes a separate list element, preventing shell injection. The user-controlled paths are now passed as literal arguments to the subprocess, not interpreted by a shell.

## Behaviour changes

None. The subprocess.run() call with `shell=False` and an argument list still:
- Raises `CalledProcessError` when the command exits with non-zero status (due to `check=True`)
- Allows stdout and stderr to be inherited by the parent process (matching original behavior of not capturing them)
- Blocks until the command completes
- Returns the same `CompletedProcess` object to the caller

Verification: Python 3 syntax check passed via `python -m py_compile`.
